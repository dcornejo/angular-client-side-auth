var User
    , _ =               require('underscore')
    , passport =        require('passport')
    , LocalStrategy =   require('passport-local').Strategy
    , TwitterStrategy = require('passport-twitter').Strategy
    , FacebookStrategy = require('passport-facebook').Strategy
    , GoogleStrategy =  require('passport-google-oauth').OAuth2Strategy
    , LinkedInStrategy = require('passport-linkedin').Strategy
    , check =           require('validator').check
    , userRoles =       require('../../client/js/routingConfig').userRoles;

var users = [
    {
        id:         1,
        username:   "user",
        password:   "123",
        role:   userRoles.user
    },
    {
        id:         2,
        username:   "admin",
        password:   "123",
        role:   userRoles.admin
    }
];

module.exports = {
    addUser: function(username, password, role, callback) {
        this.findByUsername(username, function () {
            return callback("UserAlreadyExists");
        });

        // Clean up when 500 users reached
        if(users.length > 500) {
            users = users.slice(0, 2);
        }

        var user = {
            id:         _.max(users, function(user) { return user.id; }).id + 1,
            username:   username,
            password:   password,
            role:       role
        };
        users.push(user);
        callback(null, user);
    },

    findOrCreateOauthUser: function(provider, providerId, displayName, callback) {
        module.exports.findByProviderId(provider, providerId, function (user) {
            if(!user) {
                user = {
                    id: _.max(users, function(user) { return user.id; }).id + 1,
                    username: displayName,
                    role: userRoles.user,
                    provider: provider
                };
                user[provider] = providerId;
                users.push(user);
            }
            callback (user);
        });
    },

    findAll: function(callback) {
        callback (_.map(users, function(user) { return _.clone(user); }));
    },

    findById: function(id, callback) {
        callback (_.clone(_.find(users, function(user) { return user.id === id })));
    },

    findByUsername: function(username, callback) {
        callback (_.clone(_.find(users, function(user) { return user.username === username; })));
    },

    findByProviderId: function(provider, id, callback) {
        callback (_.find(users, function(user) { return user[provider] === id; }));
    },

    validate: function(user) {
        check(user.username, 'Username must be 1-20 characters long').len(1, 20);
        check(user.password, 'Password must be 5-60 characters long').len(5, 60);
        check(user.username, 'Invalid username').not(/((([A-Za-z]{3,9}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)/);

        // TODO: Seems node-validator's isIn function doesn't handle Number arrays very well...
        // Till this is rectified Number arrays must be converted to string arrays
        // https://github.com/chriso/node-validator/issues/185
        var stringArr = _.map(_.values(userRoles), function(val) { return val.toString() });
        check(user.role, 'Invalid user role given').isIn(stringArr);
    },

    localStrategy: new LocalStrategy(
        function(username, password, done) {

            module.exports.findByUsername(username, function (user) {
                if(!user) {
                    done(null, false, { message: 'Incorrect username.' });
                }
                else if(user.password != password) {
                    done(null, false, { message: 'Incorrect username.' });
                }
                else {
                    return done(null, user);
                }
            });
        }
    ),

    twitterStrategy: function() {
        if(!process.env.TWITTER_CONSUMER_KEY)    throw new Error('A Twitter Consumer Key is required if you want to enable login via Twitter.');
        if(!process.env.TWITTER_CONSUMER_SECRET) throw new Error('A Twitter Consumer Secret is required if you want to enable login via Twitter.');

        return new TwitterStrategy({
            consumerKey: process.env.TWITTER_CONSUMER_KEY,
            consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
            callbackURL: process.env.TWITTER_CALLBACK_URL || 'http://localhost:8000/auth/twitter/callback'
        },
        function(token, tokenSecret, profile, done) {
            var user = module.exports.findOrCreateOauthUser(profile.provider, profile.id);
            done(null, user);
        });
    },

    facebookStrategy: function() {
        if(!process.env.FACEBOOK_APP_ID)     throw new Error('A Facebook App ID is required if you want to enable login via Facebook.');
        if(!process.env.FACEBOOK_APP_SECRET) throw new Error('A Facebook App Secret is required if you want to enable login via Facebook.');

        return new FacebookStrategy({
            clientID: process.env.FACEBOOK_APP_ID,
            clientSecret: process.env.FACEBOOK_APP_SECRET,
            callbackURL: process.env.FACEBOOK_CALLBACK_URL || "http://localhost:8000/auth/facebook/callback"
        },
        function(accessToken, refreshToken, profile, done) {
            var user = module.exports.findOrCreateOauthUser(profile.provider, profile.id);
            done(null, user);
        });
    },

    googleStrategy: function() {
        if (!process.env.GOOGLE_CLIENT_ID)     throw new Error('A Google client key is required if you want to enable login via Google.');
        if (!process.env.GOOGLE_CLIENT_SECRET) throw new Error('A Google client secret is required if you want to enable login via Google.');
        if (!process.env.GOOGLE_CALLBACK_URL)  throw new Error('A Google callback URL is required if you want to enable login via Google.');

        return new GoogleStrategy({
             clientID: process.env.GOOGLE_CLIENT_ID,
             clientSecret: process.env.GOOGLE_CLIENT_SECRET,
             callbackURL: process.env.GOOGLE_CALLBACK_URL
        },
        function(accessToken, refreshToken, profile, done) {
            //console.log ('fert ' + JSON.stringify (profile._json));
            module.exports.findOrCreateOauthUser(profile.provider, profile.id, profile.displayName, function (user) {
                done(null, user);
            });
        });
    },

    linkedInStrategy: function() {
        if(!process.env.LINKED_IN_KEY)     throw new Error('A LinkedIn App Key is required if you want to enable login via LinkedIn.');
        if(!process.env.LINKED_IN_SECRET) throw new Error('A LinkedIn App Secret is required if you want to enable login via LinkedIn.');

        return new LinkedInStrategy({
            consumerKey: process.env.LINKED_IN_KEY,
            consumerSecret: process.env.LINKED_IN_SECRET,
            callbackURL: process.env.LINKED_IN_CALLBACK_URL || "http://localhost:8000/auth/linkedin/callback"
          },
           function(token, tokenSecret, profile, done) {
            var user = module.exports.findOrCreateOauthUser('linkedin', profile.id);
            done(null,user); 
          }
        );
    },
    serializeUser: function(user, done) {
        done(null, user.id);
    },

    deserializeUser: function(id, done) {
        module.exports.findById(id, function (user) {
            if (user) {
                done(null, user);
            }
            else {
                done(null, false);
            }
        });
    }
};