--
--  A Shadowsocks implement in Lua.
--  by zyxwvu <imzyxwvu@icloud.com>
--

do -- read JSON configuration
	local fp = assert(io.open(arg[1] or "local.json", "rb"))
	CONFIGURATION = fp:read"*a"
end

CONFIGURATION = (require "cjson").decode(CONFIGURATION)
assert(CONFIGURATION.server, "which server?")
assert(CONFIGURATION.password, "password?")
if CONFIGURATION.server_port then
	SERVER_PORT = assert(tonumber(CONFIGURATION.server_port))
else
	SERVER_PORT = 8388
end
CONFIGURATION.method = CONFIGURATION.method or "aes-256-cfb"

if not jit then
	error "run this program with luajit, okay?"
end

ffi, crypto = require "ffi", require "crypto"
uv = require "xuv"

local schar, band = string.char, (bit or bit32).band

function log(format, ...)
	print(os.date(" * ") .. string.format(format, ...))
end

if jit and jit.os == "Linux" then
	ffi = require "ffi"
	ffi.cdef[[void (*signal(int signum,void(* handler)(int)))(int);]]
	ffi.C.signal(13, function() end) -- Ignore SIGPIPE
end

--------------------------------------------------------------------------------
------------------------------     Shadowsocks    ------------------------------
--------------------------------------------------------------------------------

Shadowsocks = { Ciphers = {} }

function Shadowsocks.RandomString(length)
	local buffer = {}
	for i = 1, length do buffer[i] = math.random(0, 255) end
	return schar(unpack(buffer))
end

if jit.os == "Linux" then
	RPi_HWRng = io.open("/dev/hwrng", "rb")
	if RPi_HWRng then
		function Shadowsocks.RandomString(length)
			return RPi_HWRng:read(length)
		end
	end
end

function Shadowsocks.evp_bytestokey(password, key_len)
	local m, i = {}, 0
	while #(table.concat(m)) < key_len do
		local data = password
		if i > 0 then data = m[i] .. password end
		m[#m + 1], i = crypto.digest("md5", data, true), i + 1
	end
	local ms = table.concat(m)
	return ms:sub(1, key_len)
end

function Shadowsocks.OpenSSL(wtf, method, key, iv)
	return wtf.new(method, key, iv)
end

function Shadowsocks.rc4_md5(wtf, _, key, _iv)
	local md5 = crypto.digest.new "md5"
	md5:update(key)
	md5:update(iv)
	return wtf.new("rc4", md5:final(nil, true), "")
end

Shadowsocks.Ciphers["aes-256-cfb"] = { 32, 16, Shadowsocks.OpenSSL }

function Shadowsocks.Wrap(method, password)
	local cipher = assert(Shadowsocks.Ciphers[method], "no such method")
	assert(#cipher == 3, "bad cipher")
	local key = Shadowsocks.evp_bytestokey(password, cipher[1])
	return function(stream)
		local encipher_iv = Shadowsocks.RandomString(cipher[2])
		local encipher = cipher[3](crypto.encrypt, method, key, encipher_iv)
		local decipher
		stream:nodelay(true)
		if not stream:write(encipher_iv) then return end
		local agent = {}
		function agent:close() return stream:close() end
		function agent:alive() return stream() end
		function agent:read_start() return stream:read_start() end
		function agent:read_stop() return stream:read_stop() end
		function agent:write(data, callback)
			return stream:write(encipher:update(data), callback)
		end
		function stream.on_close()
			if agent.on_close then return agent.on_close() end
		end
		local function call_data_callback(chunk)
			return agent.on_data(decipher:update(chunk))
		end
		function stream.on_data(chunk)
			if decipher then
				call_data_callback(chunk)
			elseif #chunk >= cipher[2] then
				local _iv = chunk:sub(1, cipher[2])
				decipher = cipher[3](crypto.decrypt, method, key, _iv)
				if #chunk > cipher[2] then
					call_data_callback(chunk:sub(cipher[2] + 1, -1))
				end
			else -- TODO
				stream:close()
			end
		end
		return agent
	end
end

Shadowsocks.GetAgent = Shadowsocks.Wrap(CONFIGURATION.method, CONFIGURATION.password)

function service(self, request, rest)
	local first_kiss
	if request.address then
		local a, b, c, d = request.address:match "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
		a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
		assert(a and b and c and d, "not an ip address")
		local port = request.r_port
		local port_a, port_b = band(port, 0xFF00) / 0x100, band(port, 0xFF)
		first_kiss = schar(1, a, b, c, d, port_a, port_b)
	else
		first_kiss = schar(3, #request.host) .. request.host
		local port = request.r_port
		first_kiss = first_kiss .. schar(band(port, 0xFF00) / 0x100, band(port, 0xFF))
	end
	if rest then first_kiss = first_kiss .. rest end
	uv.connect(CONFIGURATION.server, SERVER_PORT, function(remote, err)
		if err then
			log("failed to connect to the Shadowsocks agent")
			request.fail()
			return
		end
		if request.socks5 then
			if not self:write(schar(0, 0, 1, 0, 0, 0, 0, 0x10, 0x10)) then
				remote:close()
				return
			end
		end
		remote = Shadowsocks.GetAgent(remote)
		if not remote:write(first_kiss) then self:close() return end
		log("connect to %s", request.host or request.address)
		function remote.on_close() self:close() end
		function self.on_close() remote:close() end
		function remote.on_data(chunk)
			remote:read_stop()
			if self() then self:write(chunk, function()
				if remote:alive() then remote:read_start() end
			end) end
		end
		function self.on_data(chunk)
			self:read_stop()
			if remote:alive() then remote:write(chunk, function()
				if self() then self:read_start() end
			end) end
		end
		remote:read_start()
		self:read_start()
	end)
end

--------------------------------------------------------------------------------
------------------------------   SOCKS5 Service   ------------------------------
--------------------------------------------------------------------------------

uv.listen("0.0.0.0", 1080, 128, function(self)
	self:nodelay(true)
	local buffer, nstage, state = "", 1, { stream = self, socks5 = true }
	local function handshake()
		if nstage == 1 then
			if #buffer >= 2 then
				local a, b = buffer:byte(1, 2)
				if a == 5 and b > 0 then
					state.nmethods = b
					nstage = 2
				elseif a == 4 and b == 1 then
					return self:close() -- do not provide socks4
				else
					-- self:read_stop()
					-- HTTP.HandleStream(self, buffer, web_service)
					-- buffer = nil
					-- return
					return self:close()
				end
				buffer = buffer:sub(3, -1)
			end
		elseif nstage == 2 then
			if #buffer >= state.nmethods then
				buffer = buffer:sub(state.nmethods + 1, -1)
				self:write "\x05\x00"
				nstage = 3
			end
		elseif nstage == 3 then
			if #buffer >= 4 then
				local v, c, r, a = buffer:byte(1, 4)
				if v == 5 and c == 1 and (a == 1 or a == 3) then
					state.atype = a
					nstage, buffer = 4, buffer:sub(5, -1)
					return true
				else
					self:write(
						"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00",
						function() self:close() end)
				end
			end
		elseif nstage == 4 then
			if state.atype == 3 then
				if #buffer >= 1 then
					state.namelen = buffer:byte(1, 1)
					nstage, buffer = "name", buffer:sub(2, -1)
				end
			else
				if #buffer >= 4 then
					local a, b, c, d = buffer:byte(1, 4)
					state.address = ("%d.%d.%d.%d"):format(a, b, c, d)
					nstage, buffer = 5, buffer:sub(5, -1)
				end
			end
		elseif nstage == "name" then
			if #buffer >= state.namelen then
				state.host = buffer:sub(1, state.namelen)
				nstage, buffer = 5, buffer:sub(state.namelen + 1, -1)
				if state.host:find("^%d+%.%d+%.%d+%.%d+$") then
					state.address = state.host
				end
			end
		elseif nstage == 5 then
			if #buffer >= 2 and self() then
				local a, b = buffer:byte(1, 2)
				state.r_port = a * 0x100 + b
				nstage, buffer = 8, buffer:sub(3, -1)
				if #buffer == 0 then buffer = nil end
				self:write "\x05"
				self:read_stop()
				self.on_data = nil
				local s, err = pcall(service, self, state, buffer)
				if not s and err then print(" * Lua error: " .. err) end
				buffer = nil
			end
		else error("never reaches here: " .. tostring(nstage)) end
	end
	function state.fail()
		if self() then
			if not self:write("\x01\x00\x01\x00\x00\x00\x00\x00\x00", function()
				self:close()
			end) then self:close() end
		end
	end
	function self.on_data(chunk)
		buffer = buffer .. chunk
		local reference_buffer
		repeat
			reference_buffer = buffer
			handshake()
			if not buffer then return end
		until reference_buffer == buffer
	end
	self:read_start()
end)

uv.run()