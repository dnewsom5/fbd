var express = require('express')
  , passport = require('passport')
  , FacebookStrategy = require('passport-facebook').Strategy
  , TripItStrategy = require('passport-tripit').Strategy
  , logger = require('morgan')
  , session = require('express-session')
  , bodyParser = require("body-parser")
  , cookieParser = require("cookie-parser")
  , methodOverride = require('method-override')
  , querystring = require('querystring')
  , vash = require('vash')
  , port = process.env.PORT || 3000
  , url = require('url')
  ;

var FBD_URL = process.env.FBD_URL || "http://localhost:" + port;
  
var FACEBOOK_APP_ID = process.env.FBD_FACEBOOK_APP_ID;
var FACEBOOK_APP_SECRET = process.env.FBD_FACEBOOK_APP_SECRET;


var TRIPIT_API_KEY = process.env.FBD_TRIPIT_APP_ID;
var TRIPIT_API_SECRET = process.env.FBD_TRIPIT_APP_SECRET;


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Facebook profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});


var app = express();

// configure Express
  app.set('views', __dirname + '/views');
  app.set('view engine', 'vash');
  app.use(logger());
  app.use(cookieParser());
  app.use(bodyParser());
  app.use(methodOverride());
  app.use(session({ secret: 'keyboard cat' }));
  app.use(express.static(__dirname + '/public', { maxAge: 86400000 }));

  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());



// Use the FacebookStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Facebook
//   profile), and invoke a callback with a user object.
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: FBD_URL + "/auth/facebook/callback"
},
  function (accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
        
        // To keep the example simple, the user's Facebook profile is returned to
        // represent the logged-in user.  In a typical application, you would want
        // to associate the Facebook account with a user record in your database,
        // and return that user instead.
        return done(null, profile);
    });
}
));

passport.use(new TripItStrategy({
    consumerKey: TRIPIT_API_KEY,
    consumerSecret: TRIPIT_API_SECRET,
    callbackURL: FBD_URL + "/auth/tripit/callback", 
    sessionKey: 'TripitSessionKey'
},
function (token, tokenSecret, profile, done) {
    // asynchronous verification, for effect...
    
    console.log('no way: ' + token);
    console.log('no way secret: ' + tokenSecret);

    process.nextTick(function () {
        // To keep the example simple, the user's TripIt profile is returned to
        // represent the logged-in user. In a typical application, you would want
        // to associate the TripIt account with a user record in your database,
        // and return that user instead.
        return done(null, profile);
    });
}
));

var OAuth = require('oauth').OAuth;
var tripItOauth = new OAuth('https://api.tripit.com/oauth/request_token',
    'https://api.tripit.com/oauth/access_token',
    TRIPIT_API_KEY, TRIPIT_API_SECRET, '1.0',
    null, 'HMAC-SHA1');


app.get('/', function (req, res) {
  res.render('index', { user: req.user, sess: req.session });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user });
});

// GET /auth/facebook
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Facebook authentication will involve
//   redirecting the user to facebook.com.  After authorization, Facebook will
//   redirect the user back to this application at /auth/facebook/callback
app.get('/auth/facebook',
  passport.authenticate('facebook'),
  function(req, res){
    // The request will be redirected to Facebook for authentication, so this
    // function will not be called.
  });

// GET /auth/facebook/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/facebook/callback', 
  passport.authenticate('facebook', { failureRedirect: '/index' }),
  function(req, res) {
    res.redirect('/');
  });


// GET /auth/tripit
// Use passport.authenticate() as route middleware to authenticate the
// request. The first step in TripIt authentication will involve redirecting
// the user to tripit.com. After authorization, TripIt will redirect the user
// back to this application at /auth/tripit/callback
app.get('/auth/tripit',
    passport.authenticate('tripit'),
    function (req, res) {
    // The request will be redirected to TripIt for authentication, so this
    // function will not be called.
});

// GET /auth/tripit/callback
// Use passport.authenticate() as route middleware to authenticate the
// request. If authentication fails, the user will be redirected back to the
// login page. Otherwise, the primary route function function will be called,
// which, in this example, will redirect the user to the home page.
app.get('/auth/tripit/callback',
    passport.authenticate('tripit', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/');
});



app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});



app.get('/auth/tripit/connect', function (req, res) {
    
    consumer = tripItOauth;
 
    consumer.getOAuthRequestToken(function (err, oauth_token, oauth_token_secret, results) {
        console.log('==>We got the the request token');
        console.log(arguments);

        if (err) {
            req.session.csontos = "failure";
            console.log(err);
            res.redirect('/');
        } else {
            //we store these in the session until the callback, at which point we delete these and then we will store the authorized credentials in a database
            req.session.tripit_oauth_token = oauth_token;
            req.session.tripit_oauth_token_secret = oauth_token_secret;


            var parsed = url.parse('https://www.tripit.com/oauth/authorize', true);
            parsed.query['oauth_token'] = oauth_token;
            parsed.query['oauth_callback'] = FBD_URL + '/auth/tripit/callback2';
            delete parsed.search;

            var location = url.format(parsed);
            res.redirect(location);
        }
    })
});



app.get('/auth/tripit/callback2', function (req, res) {
   
    console.log('==>handleTripItAuthenticateCallback');
    
    var oauth_token = req.query['oauth_token'];
    var oauthVerifier = req.query['oauth_verifier'] || null;
    var oauth_token_secret = req.session.tripit_oauth_token_secret;
    
    if (!oauth_token) {
        console.log('==>handleTripItAuthenticateCallback - ugh. no oauth_token');
        res.redirect('/login');
    }
    
    delete req.session.tripit_oauth_token;
    delete req.session.tripit_oauth_token_secret;
        
    console.log('temp secret:' + oauth_token_secret)
    
    // Get the authorized access_token with the un-authorized one.
    tripItOauth.getOAuthAccessToken(oauth_token, oauth_token_secret, function (err, oauth_access_token, oauth_access_token_secret, results) {
        console.log('==>Get the access token');
        console.log(arguments);
        
   
        console.log('access secret:' + oauth_access_token_secret)
        if (!err) {
            
            req.session.tripit_oauth_access_token = oauth_access_token //ideally we store this somewhere better
            req.session.tripit_oauth_access_secret = oauth_access_token_secret //ideally we store this somewhere better

            // Access the protected resource with access token
            var url = 'https://api.tripit.com/v1/get/profile?format=json';
            tripItOauth.get(url, oauth_access_token, oauth_access_token_secret, function (err, data, response) {
                console.log('==>Access Tripit Profile');
                console.log('current secret:' + req.session.tripit_oauth_access_secret);
                console.log(err);
                console.log(data);
                res.redirect('/')
            });
        }
    });
});


app.get('/trips', function (req, res) {
    
    var oauth_access_token = req.session.tripit_oauth_access_token;
    var oauth_access_token_secret = req.session.tripit_oauth_access_secret;
    
    if (!oauth_access_token_secret) {
        
        res.redirect('/auth/tripit/connect');
    }
    
    console.log('==>Access Tripit Trips');
    console.log('access token:' + oauth_access_token)
    console.log('access secret:' + oauth_access_token_secret)

    // Access the protected resource with access token
    var url = 'https://api.tripit.com/v1/list/trip?format=json';
    tripItOauth.get(url, oauth_access_token, oauth_access_token_secret, function (err, data, response) {
        console.log('==>Access Tripit Trips Response');
        console.log(err);
        console.log(data);
        
        var json = JSON.parse(data);

        if (!err) {
            if (!Array.isArray(json)) {
                //tripit's JSON is really bad. If there is just one trip, then they don't return an array.
                json = [json];
            }

            res.render('trips', { trips: json });
        }
    });
});


app.listen(port);

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
