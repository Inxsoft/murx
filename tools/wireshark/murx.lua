-- Wireshark dissector for MURX (Multi-User Resource eXchange), spec revision 1.1.
--
-- Install: copy to your Wireshark personal plugins folder
--   Linux/macOS: ~/.local/lib/wireshark/plugins/   Windows: %APPDATA%\Wireshark\plugins\
-- or run:  wireshark -X lua_script:murx.lua   /   tshark -X lua_script:murx.lua
--
-- Decodes TCP and UDP port 2743: packet fields, signed tokens, and the UDP
-- authentication trailer. It does not verify MACs, since that needs node secrets.

local murx = Proto("murx", "MURX (Multi-User Resource eXchange)")

local OPCODES = {
    [0x01] = "AUTH_CONNECT", [0x02] = "ROUTE_REDIRECT", [0x03] = "AUTH_REJECT",
    [0x10] = "NODE_ANNOUNCE", [0x11] = "NODE_HEARTBEAT", [0x12] = "HEARTBEAT_ACK",
}
local FAMILIES = { [0x03] = "DNS name", [0x04] = "IPv4", [0x06] = "IPv6" }
local REASONS = {
    [0x01] = "Invalid credentials", [0x02] = "No route", [0x03] = "Malformed request",
    [0x04] = "Unsupported version", [0xFF] = "Internal error",
}

local f = {
    length      = ProtoField.uint16("murx.length", "Length", base.DEC),
    version     = ProtoField.uint8("murx.version", "Version", base.DEC),
    opcode      = ProtoField.uint8("murx.opcode", "Opcode", base.HEX, OPCODES),
    client_id   = ProtoField.string("murx.client_id", "Client ID"),
    auth_data   = ProtoField.bytes("murx.auth_data", "Auth Data"),
    family      = ProtoField.uint8("murx.family", "Address Family", base.HEX, FAMILIES),
    ipv4        = ProtoField.ipv4("murx.ipv4", "Address"),
    ipv6        = ProtoField.ipv6("murx.ipv6", "Address"),
    hostname    = ProtoField.string("murx.hostname", "Host Name"),
    port        = ProtoField.uint16("murx.port", "Port", base.DEC),
    token       = ProtoField.bytes("murx.token", "Auth Token"),
    tok_version = ProtoField.uint8("murx.token.version", "Token Version", base.DEC),
    tok_expiry  = ProtoField.absolute_time("murx.token.expiry", "Expiry", base.UTC),
    tok_nonce   = ProtoField.bytes("murx.token.nonce", "Nonce"),
    tok_node    = ProtoField.string("murx.token.node_id", "Node ID"),
    tok_client  = ProtoField.string("murx.token.client_id", "Client ID"),
    tok_mac     = ProtoField.bytes("murx.token.mac", "MAC"),
    reason      = ProtoField.uint8("murx.reason", "Reason Code", base.HEX, REASONS),
    reason_text = ProtoField.string("murx.reason_text", "Reason Text"),
    capacity    = ProtoField.uint16("murx.capacity", "Capacity", base.DEC),
    node_id     = ProtoField.string("murx.node_id", "Node ID"),
    load        = ProtoField.uint8("murx.load", "Load", base.DEC),
    udp_ts      = ProtoField.uint64("murx.udp.timestamp", "Timestamp (ms)", base.DEC),
    udp_mac     = ProtoField.bytes("murx.udp.mac", "MAC"),
}
murx.fields = {}
for _, field in pairs(f) do table.insert(murx.fields, field) end

local e_malformed = ProtoExpert.new("murx.malformed", "Malformed MURX packet", expert.group.MALFORMED, expert.severity.ERROR)
murx.experts = { e_malformed }

-- Each helper returns the new offset, or nil if the buffer is too short.
local function need(tvb, off, n) return off + n <= tvb:len() end

local function lv_string(tvb, tree, off, field)
    if not need(tvb, off, 1) then return nil end
    local n = tvb(off, 1):uint()
    if not need(tvb, off + 1, n) then return nil end
    tree:add(field, tvb(off + 1, n))
    return off + 1 + n, tvb(off + 1, n):string()
end

local function address(tvb, tree, off)
    if not need(tvb, off, 1) then return nil end
    local fam = tvb(off, 1):uint()
    tree:add(f.family, tvb(off, 1))
    off = off + 1
    if fam == 0x04 and need(tvb, off, 4) then
        tree:add(f.ipv4, tvb(off, 4)); return off + 4, tostring(tvb(off, 4):ipv4())
    elseif fam == 0x06 and need(tvb, off, 16) then
        tree:add(f.ipv6, tvb(off, 16)); return off + 16, tostring(tvb(off, 16):ipv6())
    elseif fam == 0x03 then
        return lv_string(tvb, tree, off, f.hostname)
    end
    return nil
end

local function token(tvb, tree, off, n)
    local t = tree:add(f.token, tvb(off, n))
    -- Signed token: ver(1) expiry(8) nonce(16) nid_len(1) nid cid_len(1) cid mac(16)
    if n < 43 or tvb(off, 1):uint() ~= 1 then return end
    t:add(f.tok_version, tvb(off, 1))
    local secs = tvb(off + 1, 8):uint64():tonumber()
    t:add(f.tok_expiry, tvb(off + 1, 8), NSTime.new(secs, 0))
    t:add(f.tok_nonce, tvb(off + 9, 16))
    local p = off + 25
    local nid = tvb(p, 1):uint()
    if p + 1 + nid + 1 > off + n - 16 then return end
    t:add(f.tok_node, tvb(p + 1, nid))
    p = p + 1 + nid
    local cid = tvb(p, 1):uint()
    if p + 1 + cid ~= off + n - 16 then return end
    t:add(f.tok_client, tvb(p + 1, cid))
    t:add(f.tok_mac, tvb(off + n - 16, 16))
end

local function dissect_packet(tvb, pinfo, tree)
    if tvb:len() < 2 then tree:add_proto_expert_info(e_malformed); return end
    tree:add(f.version, tvb(0, 1))
    local op = tvb(1, 1):uint()
    tree:add(f.opcode, tvb(1, 1))
    local name = OPCODES[op] or string.format("Unknown (0x%02x)", op)
    local info = name
    local off, ok, s = 2, true, nil

    if op == 0x01 then
        off, s = lv_string(tvb, tree, off, f.client_id)
        if off and need(tvb, off, 2) then
            local n = tvb(off, 2):uint()
            if need(tvb, off + 2, n) then tree:add(f.auth_data, tvb(off + 2, n)) else ok = false end
            info = info .. " client=" .. s
        else ok = false end
    elseif op == 0x02 then
        off, s = address(tvb, tree, off)
        if off and need(tvb, off, 3) then
            tree:add(f.port, tvb(off, 2))
            local n = tvb(off + 2, 1):uint()
            info = string.format("%s -> %s:%d", info, s, tvb(off, 2):uint())
            if need(tvb, off + 3, n) then token(tvb, tree, off + 3, n) else ok = false end
        else ok = false end
    elseif op == 0x03 then
        if need(tvb, off, 2) then
            tree:add(f.reason, tvb(off, 1))
            local n = tvb(off + 1, 1):uint()
            if need(tvb, off + 2, n) and n > 0 then tree:add(f.reason_text, tvb(off + 2, n)) end
            info = info .. " " .. (REASONS[tvb(off, 1):uint()] or "unknown reason")
        else ok = false end
    elseif op == 0x10 then
        off, s = address(tvb, tree, off)
        if off and need(tvb, off, 4) then
            tree:add(f.port, tvb(off, 2)); tree:add(f.capacity, tvb(off + 2, 2))
            local port = tvb(off, 2):uint()
            local nid
            off, nid = lv_string(tvb, tree, off + 4, f.node_id)
            if off then info = string.format("%s node=%s at %s:%d", info, nid, s, port) else ok = false end
        else ok = false end
    elseif op == 0x11 then
        local nid
        off, nid = lv_string(tvb, tree, off, f.node_id)
        if off and need(tvb, off, 1) then
            tree:add(f.load, tvb(off, 1))
            info = string.format("%s node=%s load=%d", info, nid, tvb(off, 1):uint())
        else ok = false end
    end

    if not ok then tree:add_proto_expert_info(e_malformed) end
    pinfo.cols.info:append((tostring(pinfo.cols.info) ~= "" and ", " or "") .. info)
end

local function tcp_pdu_len(tvb, pinfo, off)
    return 2 + tvb(off, 2):uint()
end

local function dissect_tcp_pdu(tvb, pinfo, tree)
    pinfo.cols.protocol = "MURX"
    local t = tree:add(murx, tvb(), "MURX (TCP)")
    t:add(f.length, tvb(0, 2))
    dissect_packet(tvb(2):tvb(), pinfo, t)
    return tvb:len()
end

local murx_tcp = Proto("murx_tcp", "MURX over TCP")
function murx_tcp.dissector(tvb, pinfo, tree)
    pinfo.cols.info = ""
    dissect_tcp_pdus(tvb, tree, 2, tcp_pdu_len, dissect_tcp_pdu)
    return tvb:len()
end

local murx_udp = Proto("murx_udp", "MURX over UDP")
function murx_udp.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "MURX"
    pinfo.cols.info = ""
    local t = tree:add(murx, tvb(), "MURX (UDP)")
    local n = tvb:len()
    if n < 26 then
        dissect_packet(tvb, pinfo, t)
        t:add_proto_expert_info(e_malformed, "Missing authentication trailer")
        return n
    end
    dissect_packet(tvb(0, n - 24):tvb(), pinfo, t)
    local trailer = t:add(tvb(n - 24, 24), "Authentication trailer")
    trailer:add(f.udp_ts, tvb(n - 24, 8))
    trailer:add(f.udp_mac, tvb(n - 16, 16))
    return n
end

DissectorTable.get("tcp.port"):add(2743, murx_tcp)
DissectorTable.get("udp.port"):add(2743, murx_udp)
