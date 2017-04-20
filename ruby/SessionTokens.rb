java_import 'burp.IBurpExtender'
java_import 'burp.ISessionHandlingAction'

SESSION_ID_KEY = "X-Custom-Session-Id:"
SESSION_ID_KEY_BYTES = SESSION_ID_KEY.bytes.to_a
NEWLINE_BYTES = "\r\n".bytes.to_a

class BurpExtender
  include IBurpExtender, ISessionHandlingAction

  #
  # implement IBurpExtender
  #

  def registerExtenderCallbacks(callbacks)
    # save the helpers for later
    @helpers = callbacks.getHelpers

    # set our extension name
    callbacks.setExtensionName "Session token example"
    callbacks.registerSessionHandlingAction self
  end

  #
  # Implement ISessionHandlingAction
  #

  def getActionName()
    "Use session token from macro"
  end

  def performAction(current_request, macro_items)
    return if macro_items.empty?

    # extract the response headers
    final_response = macro_items[macro_items.length - 1].getResponse
    return if final_response.nil?

    headers = @helpers.analyzeResponse(final_response).getHeaders

    session_token = nil
    for header in headers
      # skip any header that isn't an "X-Custom-Session-Id"
      next if not header.start_with? SESSION_ID_KEY

      # grab the session token
      session_token = header[SESSION_ID_KEY.length..-1].strip
    end

    # if we failed to find a session token, stop doing work
    return if session_token.nil?

    req = current_request.getRequest

    session_token_key_start = @helpers.indexOf(req, SESSION_ID_KEY_BYTES, false, 0, req.length)
    session_token_key_end = @helpers.indexOf(req, NEWLINE_BYTES, false, session_token_key_start, req.length)

    # glue together first line + session token header + rest of request
    current_request.setRequest(
          req[0...session_token_key_start] +
          "#{SESSION_ID_KEY} #{session_token}".bytes.to_a +
          req[session_token_key_end..-1])
  end
end
