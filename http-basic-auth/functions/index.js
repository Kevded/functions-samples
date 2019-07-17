/**
 * Copyright 2017 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for t`he specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const functions = require('firebase-functions');

// CORS Express middleware to enable CORS Requests.
const cors = require('cors')({origin: true});
exports.auth = functions.https.onRequest((req, res) => {
 
    // check for basic auth header
    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
      res.status(401).setHeader("WWW-Authenticate", "Basic");
      return res.end();
  }

  // verify auth credentials
  const base64Credentials = req.headers.authorization.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');
  if (username === "demo" && password === "demo") {
      console.log(user, "successfully logged in");
      res.status(200).setHeader("Content-Type", "text/plain");
      return res.send("ok")
  }
  console.log(user, "failed to logged in with password: ", password);
  res.status(401).setHeader("WWW-Authenticate", "Basic");
  return res.send("Unauthorized");

});

