package burp;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction
{
    private static final String SESSION_ID_KEY = "X-Custom-Session-Id:";
    private static final byte[] SESSION_ID_KEY_BYTES = SESSION_ID_KEY.getBytes();
    private static final byte[] NEWLINE_BYTES = new byte[] { '\r', '\n' };

    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // save the helpers for later
        this.helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Session token example");
        callbacks.registerSessionHandlingAction(this);
    }

    //
    // Implement ISessionHandlingAction
    //

    @Override
    public String getActionName()
    {
        return "Use session token from macro";
    }

    @Override
    public void performAction(
            IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems)
    {
        if (macroItems.length == 0) return;

        // extract the response headers
        final byte[] finalResponse = macroItems[macroItems.length - 1].getResponse();
        if (finalResponse == null) return;

        final List<String> headers = helpers.analyzeResponse(finalResponse).getHeaders();

        String sessionToken = null;
        for (String header : headers)
        {
            // skip any header that isn't an "X-Custom-Session-Id"
            if (!header.startsWith(SESSION_ID_KEY)) continue;

            // grab the session token
            sessionToken = header.substring((SESSION_ID_KEY).length()).trim();
        }

        // if we failed to find a session token, stop doing work
        if (sessionToken == null) return;

        final byte[] req = currentRequest.getRequest();

        final int sessionTokenKeyStart = helpers.indexOf(req, SESSION_ID_KEY_BYTES, false, 0, req.length);
        final int sessionTokenKeyEnd = helpers.indexOf(req, NEWLINE_BYTES, false, sessionTokenKeyStart, req.length);

        // glue together first line + session token header + rest of request
        currentRequest.setRequest(join(
                    Arrays.copyOfRange(req, 0, sessionTokenKeyStart),
                    helpers.stringToBytes(String.format("%s %s", SESSION_ID_KEY, sessionToken)),
                    Arrays.copyOfRange(req, sessionTokenKeyEnd, req.length)
        ));
    }

    private static byte[] join(byte[]... arrays)
    {
        int len = 0;
        for (byte[] arr : arrays)
        {
            len += arr.length;
        }

        byte[] result = new byte[len];
        int idx = 0;

        for (byte[] arr : arrays)
        {
            for (byte b : arr)
            {
                result[idx++] = b;
            }
        }

        return result;
    }
}
