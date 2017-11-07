local json = require("cjson")
local zlib = require("zlib")
local resty_cookie = require("resty.cookie")

local uri_args = ngx.req.get_uri_args()

local client_secret = oauth_client_secret or ngx.var.oauth_client_secret
local client_id = oauth_client_id or ngx.var.oauth_client_id

local scope = oauth_scope or ngx.var.oauth_scope or 'read:org'

local valid_org = oauth_org or ngx.var.oauth_org
local token_secret = oauth_token_secret or ngx.var.oauth_token_secret or 'notsosecret'

local proxy_api_uri = oauth_proxy_api_uri or ngx.var.oauth_proxy_api_uri or '/_oauth/api/'
local access_token_uri = oauth_access_token_uri or ngx.var.oauth_access_token_uri or '/_oauth/access_token'

local blacklist_string = oauth_blacklist or ngx.var.oauth_blacklist or ''
local blacklist = string.gmatch(blacklist_string, "%S+")

local domain = oauth_domain or ngx.var.oauth_domain or ngx.var.host
local max_age = oauth_max_age or ngx.var.oauth_max_age or 3600

local function handle_subrequest_error(response)
    if not response then
        return "failed"
    end

    if response.status ~= 200 then
        return "failed with " .. response.status .. ": " .. response.body
    end

    return nil
end

local function request_access_token(code)
    ngx.log(ngx.INFO, 'Requesting access token with code ' .. code)
    local res = ngx.location.capture(
        access_token_uri,
        { method=ngx.HTTP_POST
        , args={ client_id=client_id
               , client_secret=client_secret
               , code=code
               }})
    err = handle_subrequest_error(res)
    if err then
        ngx.log(ngx.ERR, "Got error during access token request: " .. err)
        ngx.header['Content-type'] = 'text/html'
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("Got error during access token request: " .. err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    else
        ngx.log(ngx.DEBUG, "Decoded access token request: " .. res.body)
        return ngx.decode_args(res.body)
    end
end

local function provider_api_request(api_uri, token)
    local api_request_uri = proxy_api_uri .. api_uri
    ngx.log(ngx.INFO, 'Making subrequest to ' .. api_request_uri .. " with token " .. token)

    ngx.req.set_header('Authorization', "token " .. token)
    local api_response = ngx.location.capture(api_request_uri)
    err = handle_subrequest_error(api_response)
    if err then
        ngx.log(ngx.ERR, "Got error during request to " .. api_uri .. ": " .. err)
        ngx.header['Content-type'] = 'text/html'
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("Got error during request to " .. api_uri .. ": " .. err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    else
        local stream = zlib.inflate()
        local status, inflated_body = pcall(stream, api_response.body)
        if not status then
          ngx.log(ngx.ERR, 'Failed to inflate response from ' .. api_request_uri .. " with token " .. token)
          inflated_body = api_response.body
        end
        ngx.log(ngx.DEBUG, 'api response body: ' .. inflated_body)
        local decoded_body = json.decode(inflated_body)
        return decoded_body
    end
end

local function validate_orgs(access_token)
    local orgs = provider_api_request('user/orgs', access_token)
    for _, org in pairs(orgs) do
        if org["login"] == valid_org then
            ngx.log(ngx.INFO, "User " .. login .. " is in an authorized org")
            return true
        end
    end
    ngx.log(ngx.ERR, "User " .. login .. " not in authorized org")
    return false
end

local function validate(access_token)
    if not access_token or access_token == '' then
        ngx.log(ngx.ERR, "No access token")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    ngx.log(ngx.DEBUG, "Validating access token" .. access_token)

    local profile = provider_api_request('user', access_token)
    login = profile["login"]

    for name in blacklist do
        if login == name then
            ngx.log(ngx.ERR, "Blocking blacklisted user " .. login)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    if not validate_orgs(access_token) then
        return nil
    end

    local token = ngx.encode_base64(ngx.hmac_sha1(token_secret, domain .. login))
    return login, token
end

local function authorize()
    if uri_args["error"] then
        ngx.log(ngx.ERR, "received " .. uri_args["error"] .. " from OAuth provider")
        ngx.header['Content-type'] = 'text/html'
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("Received " .. uri_args["error"] .. " from OAuth provider")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if not uri_args["code"] then
        ngx.log(ngx.ERR, "Invalid request: no code for authorization")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local access_token_response = request_access_token(uri_args["code"])
    access_token = access_token_response.access_token

    local login, token = validate(access_token)

    if not token then
        ngx.log(ngx.ERR, "Failed to authenticate request")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local cookie, err = resty_cookie:new()
    if not cookie then
        ngx.log(ngx.ERR, err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local ok, err = cookie:set({
        key = "OAuthLogin",
        value = ngx.escape_uri(login),
        path = "/",
        domain = domain,
        httponly = true,
        max_age = max_age
    })

    if not ok then
        ngx.log(ngx.ERR, err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local ok, err = cookie:set({
        key = "OAuthAccessToken",
        value = ngx.escape_uri(token),
        path = "/",
        domain = domain,
        httponly = true,
        max_age = max_age
    })

    if not ok then
        ngx.log(ngx.ERR, err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local redirect = uri_args['target_uri'] or '/'
    ngx.log(ngx.DEBUG, "Redirecting to " .. redirect)
    return ngx.redirect(redirect)
end

authorize()
