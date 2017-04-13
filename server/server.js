const http = require('http');

const PORT = 8000;

const SESSION_ID_KEY = 'X-Custom-Session-Id' 

const parseQueryString = str => str
  .split('&')
  .map(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return null;
    return [pair.substr(0, idx), pair.substr(idx+1)];
  })
  .reduce((acc, kvp) => {
    if (kvp !== null) acc[unescape(kvp[0])] = unescape(kvp[1]);
    return acc;
  }, {});

const SESSIONS = [];

console.log(`Serving on http://localhost:${PORT}, press ctrl+c to stop`);
http.createServer((req, res) => {
  if (req.url == "/session") {
    if (SESSION_ID_KEY.toLowerCase() in req.headers && parseInt(req.headers[SESSION_ID_KEY.toLowerCase()]) in SESSIONS) {
      const session = parseInt(req.headers[SESSION_ID_KEY.toLowerCase()]);
      if (req.method === 'POST') {
        const body = [];
        req.on('data', chunk => {
          body.push(chunk);
        }).on('end', () => {
          SESSIONS[session] += Buffer.concat(body).toString();
          res.end(SESSIONS[session]);
        });
      } else {
        res.end(SESSIONS[session]);
      }
    } else {
      const sessionId = Math.round(Math.random() * 10000);
      SESSIONS[sessionId] = "";
      res.setHeader(SESSION_ID_KEY, sessionId);
      res.end(SESSIONS[sessionId]);
    }
  } else {
    res.end(`
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
    <title>Demo</title>
</head>
<body>
    <form id=form>
    Input: <input type="text" name="input" />
    <input type="submit" value="Submit" />
    </form>
    <br />
    <div id=session></div>

    <script type="text/javascript">
      sessionId = null;

      function updateSession(data) {
        if (sessionId === null) {
          // get session id
          return fetch("session")
            .then(function (res) {
              sessionId = res.headers.get('${SESSION_ID_KEY}');
              return updateSession(data);
            });
        } else {
          var h = new Headers();
          h.append('${SESSION_ID_KEY}', sessionId);

          return fetch("session", {method: 'POST', body: data, headers: h})
            .then(function (res) {
              return res.text();
            });
        }
      }

      document.getElementById("form").onsubmit = function ()
      {
          updateSession(document.forms[0].input.value)
            .then(function (data) {
              document.getElementById("session").innerHTML = data;
            });

          return false;
      };
    </script>
</body>
</html>
    `);
  }
}).listen(PORT, 'localhost');
