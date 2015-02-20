--
--  ZyWebD express edition for shadowsocks-lua
--  (c) 2015 zyxwvu <imzyxwvu@icloud.com>
--
--  NOTE: features not included:
--  FastCGI backend, General Server, SSL Server, HandleRequest, and built-in MIMES
--
local uv = require "xuv"
local crunning, cresume, cyield = coroutine.running, coroutine.resume, coroutine.yield
local schar, sformat, tconcat, mmin = string.char, string.format, table.concat, math.min
local HTTP = { Reader = {}, Response = {}, Backend = uv, Timeout = 10000 }

local function SafeResume(co, ...)
	local s, err = cresume(co, ...)
	if not s then print(debug.traceback(co, err)) end
end

HTTP.ServerVer = "ZyWebD/15.02; " .. _VERSION
HTTP.DefaultDoc = { "index.html" }
HTTP.PathSep = package.config:sub(1, 1)

function HTTP.UrlDecode(is)
	return is:gsub("%%([A-Fa-f0-9][A-Fa-f0-9])", function(m) return schar(tonumber(m, 16)) end)
end

HTTP.Decoders = {}

HTTP.Decoders["HTTP Request"] = function(buffer)
	local l, r = buffer:find("\r?\n\r?\n")
	if l and r then
		assert(l - 1 > 1, "empty request")
		local head = buffer:sub(1, l - 1)
		local result, firstLine = {}, true
		for l in head:gmatch("([^\r\n]+)") do
			if firstLine then
				local verb, resource = l:match("^([A-Z]+) ([^%s]+) HTTP/1%.[01]$")
				assert(verb and resource, "bad request")
				result.method, result.resource_orig = verb, resource
				local resource2, querystr = resource:match("^([^%?]+)%??(.*)")
				result.headers = {}
				result.resource, result.query = HTTP.UrlDecode(resource2), querystr
				firstLine = false
			else
				local k, v = l:match("^([A-Za-z0-9%-]+):%s?(.+)$")
				assert(k and v, "bad request")
				result.headers[k:lower()] = v
			end
		end
		return result, buffer:sub(r + 1, -1)
	elseif #buffer > 0x10000 then -- impossible for a header to be larger than 64K
		error "header too long" -- notify the reader to stop reading from the stream
	end
end

function HTTP.Decoders.Line(buffer)
	local l, r = buffer:find("\r?\n")
	if l and r then
		if r < #buffer then -- in case there's something left
			return buffer:sub(1, l - 1), buffer:sub(r + 1, -1)
		else return buffer:sub(1, l - 1) end
	end
end

HTTP.SafeResume = SafeResume
HTTP.Reader_MT = { __index = HTTP.Reader }
HTTP.Response_MT = { __index = HTTP.Response }

function HTTP.Reader:Push(str, err)
	if not str then
		self.stopped = true
		if self.decoder then
			SafeResume(self.readco, nil, err or "stopped")
		end
		if self.watchdog then uv.close(self.watchdog) end
	elseif self.buffer then
		self.buffer = self.buffer .. str
		if self.decoder then
			local s, result, rest = pcall(self.decoder, self.buffer)
			if not s then
				SafeResume(self.readco, nil, result)
			elseif result then
				if rest and #rest > 0 then
					self.buffer = rest
				else
					self.buffer = nil
				end
				SafeResume(self.readco, result)
			end
		end
	else
		if self.decoder then
			local s, result, rest = pcall(self.decoder, str)
			if not s then
				self.buffer = str
				SafeResume(self.readco, nil, result)
			elseif result then
				if rest and #rest > 0 then self.buffer = rest end
				SafeResume(self.readco, result)
			else self.buffer = str end
		else self.buffer = str end
	end
end

function HTTP.Reader:Decode(decoder_name)
	assert(not self.decoder, "already reading")
	local decoder = HTTP.Decoders[decoder_name] or decoder_name
	if self.buffer then
		local s, result, rest = pcall(decoder, self.buffer)
		if not s then
			return nil, result
		elseif result then
			if rest and #rest > 0 then
				self.buffer = rest
			else
				self.buffer = nil
			end
			return result
		end
	end
	if self.stopped then return nil, "stopped" end
	self.readco, self.decoder = crunning(), decoder
	if self.watchdog then
		uv.timer_start(self.watchdog, function()
			uv.timer_stop(self.watchdog)
			SafeResume(self.readco, nil, "timeout")
		end, self.decode_timeout)
		local result, err = cyield()
		self.readco, self.decoder = nil, nil
		uv.timer_stop(self.watchdog)
		return result, err
	else
		local result, err = cyield()
		self.readco, self.decoder = nil, nil
		return result, err
	end
end

function HTTP.Reader:Read(len)
	local readSome = function(buffer)
		if #buffer <= len then return buffer elseif #buffer > len then
			return buffer:sub(1, len), buffer:sub(len + 1, -1)
		end
	end
	local cache = {}
	while len > 0 do
		local block, err = self:Decode(readSome)
		if block then
			cache[#cache + 1] = block
			len = len - #block
		else
			cache[#cache + 1] = self.buffer
			self.buffer = tconcat(cache)
			return nil, err
		end
	end
	return tconcat(cache)
end

function HTTP.Reader:Peek()
	assert(not self.decoder, "already reading")
	if self.buffer then
		local buffer = self.buffer
		self.buffer = nil
		return self.buffer
	end
	if self.stopped then return nil, "stopped" end
	self.readco, self.decoder = crunning(), function(buffer)
		return buffer
	end
	local result, err = cyield()
	self.readco, self.decoder = nil, nil
	return result, err
end

function HTTP.NewReader(timeout)
	if timeout then assert(timeout >= 100, "too short timeout") end
	local reader = { decode_timeout = timeout }
	if reader.decode_timeout then reader.watchdog = uv.new_timer() end
	return setmetatable(reader, HTTP.Reader_MT)
end

local statuscodes = {
	[100] = 'Continue', [101] = 'Switching Protocols',
	[200] = 'OK', [201] = 'Created', [202] = 'Accepted',
	[203] = 'Non-Authoritative Information',
	[204] = 'No Content', [205] = 'Reset Content', [206] = 'Partial Content',
	[300] = 'Multiple Choices', [301] = 'Moved Permanently', [302] = 'Found',
	[303] = 'See Other', [304] = 'Not Modified',
	[400] = 'Bad Request', [401] = 'Unauthorized',
	[403] = 'Forbidden', [404] = 'Not Found',
	[405] = 'Method Not Allowed', [406] = 'Not Acceptable',
	[408] = 'Request Time-out', [409] = 'Conflict', [410] = 'Gone',
	[411] = 'Length Required', [412] = 'Precondition Failed',
	[413] = 'Request Entity Too Large', [415] = 'Unsupported Media Type',
	[416] = 'Requested Range Not Satisfiable', [417] = 'Expectation Failed',
	[418] = 'I\'m a teapot', -- RFC 2324
	[500] = 'Internal Server Error', [501] = 'Not Implemented',
	[502] = 'Bad Gateway', [503] = 'Service Unavailable',
}

function HTTP.Response:RawWrite(chunk)
	if self.disabled then return nil, "disabled" end
	local s, err = self.coreWrite(self.stream, chunk, function(err)
		HTTP.SafeResume(self.thread, err)
	end)
	if s then
		if err ~= "done nothing" then -- tweak for SSL
			err = cyield()
			if err then return nil, err end
		end
		self.tx = self.tx + #chunk
		return self
	else return nil, err end
end

function HTTP.Response:Disable()
	if not self.disabled then
		self.disabled = true
		if self.on_close then self.on_close() end
	end
end

function HTTP.Response:Handled()
	return self.headerSent or self.disabled
end

function HTTP.Response:Close()
	if not self.disabled then
		self.coreClose(self.stream)
		self.disabled = true
	end
end

function HTTP.Response:WriteHeader(code, headers)
	assert(not self.headerSent, "header already sent")
	assert(statuscodes[code], "bad status code")
	local head = {
		("HTTP/1.1 %d %s"):format(code, statuscodes[code]),
		"Server: " .. HTTP.ServerVer }
	for k, v in pairs(headers) do
		if type(v) == "table" then
			for i, vv in ipairs(v) do head[#head + 1] = k .. ": " .. vv end
		else head[#head + 1] = k .. ": " .. v end
	end
	head[#head + 1] = "\r\n"
	assert(self:RawWrite(tconcat(head, "\r\n")))
	self.headerSent = code
	return self
end

function HTTP.Response:DisplayError(state, content)
	if not self:Handled() then
		self:WriteHeader(state, { ["Content-Length"] = #content, ["Content-Type"] = "text/html" })
		self:RawWrite(content)
	end
	self:Close()
end

function HTTP.Response:RedirectTo(resource)
	return self:WriteHeader(302, { ["Content-Length"] = 0, ["Location"] = resource })
end

function HTTP.ServiceLoop(sync)
	while true do
		local request = sync.reader:Decode "HTTP Request"
		if request then
			request.peername, request.ssl_port = sync.peername, sync.ssl_port
			request.reader = sync.reader
			local res = setmetatable({
				coreWrite = sync.write, coreClose = sync.close, thread = sync.thread,
				stream = sync.stream, tx = 0 }, HTTP.Response_MT)
			sync.response = res
			local s, err = pcall(sync.callback, request, res)
			if res.disabled then return end -- We can't do anything...
			if s then
				if not res.headerSent then
					local result = "Request not caught by any handler."
					res:WriteHeader(500, { ["Content-Type"] = "text/plain", ["Content-Length"] = #result })
					res:RawWrite(result)
				end
			else
				if res.headerSent then return res:Close() else
					res:DisplayError(500, ([[<!DOCTYPE html><html>
<head><title>HTTP Error 500</title></head><body><h1>500 Internal Server Error</h1><p>%s Error: <strong>%s</strong></p>
<p style="color:#83B;">* This response is generated by %s</p></body></html>]]):format(_VERSION, err, HTTP.ServerVer))
				end
			end
			if request.headers.connection then
				request.headers.connection = request.headers.connection:lower()
				if request.headers.connection ~= "keep-alive" then return res:Close() end
			else return res:Close() end
		else sync.close(sync.stream) break end
	end
end

function HTTP.HandleStream(self, rest, callback)
	local reader = HTTP.NewReader(HTTP.Timeout)
	if rest then reader:Push(rest) end
	local sync = { stream = self, reader = reader, callback = callback }
	sync.peername = self:getpeername()
	if not sync.peername then self:close(); return end
	function self.on_close(note)
		reader:Push(nil, note)
		if sync.response then sync.response:Disable() end
	end
	sync.write, sync.close = self.write, self.close
	function self.on_data(chunk) reader:Push(chunk) end
	self:read_start()
	sync.thread = coroutine.create(HTTP.ServiceLoop)
	HTTP.SafeResume(sync.thread, sync)
end

return HTTP