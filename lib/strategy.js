/**
 * Module dependencies.
 */
var util = require('util'),
	shortid = require('shortid'),
	OAuth2Strategy = require('passport-oauth2'),
	InternalOAuthError = require('passport-oauth2').InternalOAuthError;
(LineAuthorizationError = require('./errors/lineAuthorizationError')),
	(uri = require('url'));

/**
 * `Strategy` constructor.
 *
 * The Line authentication strategy authenticates requests by delegating to
 * Line using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 *
 *
 * Options (https://developers.line.biz/en/docs/line-login/integrate-line-login/#making-an-authorization-request):
 *   - `channelID`     your Line application's channel id
 *   - `channelSecret` your Line application's channel secret
 *   - `callbackURL`   URL to which Line will redirect the user after granting authorization
 * 	 - `generateState` Boolean that indicates whether a state param should be sent with the
 * 					   request (necessary for JWT/Sessionless authentication to work)
 * 	 - `scope`		   The scope of data to be accessed
 *
 *
 * Examples:
 *     passport.use(new LineStrategy({
 *         channelID: '123-456-789',
 *         channelSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/google/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
	options = options || {};
	options.clientID = options.channelID;
	options.clientSecret = options.channelSecret;
	options.generateState = options.generateState || true;
	options.scope = options.scope || ['openid', 'profile'];
	options.customHeaders = options.customHeaders || {};

	delete options.channelID;
	delete options.channelSecret;

	options.authorizationURL =
		options.authorizationURL || `https://access.line.me/oauth2/v2.1/authorize`;
	options.tokenURL =
		options.tokenURL || `https://api.line.me/oauth2/v2.1/token`;

	if (options.generateState)
		options.authorizationURL += `?state=${shortid.generate()}`;
	if (options.scopeSeparator)
		options.authorizationURL += `&scope=${options.scopeSeparator.join(' ')}`;

	OAuth2Strategy.call(this, options, verify);
	this.name = 'line';
	this._profileURL = options.profileURL || `https://api.line.me/v2/profile`;
	this._profileFields = options.profileFields || null;
	this._clientID = options.clientID;
	this._clientSecret = options.clientSecret;

	// Use Authorization Header (Bearer with Access Token) for GET requests. Used to get User's profile.
	this._oauth2.useAuthorizationHeaderforGET(true);
}

Strategy.prototype.authenticate = function (req, options) {
	if (req.query && req.query.error_code && !req.query.error) {
		return this.error(
			new LineAuthorizationError(
				req.query.error_message,
				parseInt(req.query.error_code, 10)
			)
		);
	}

	OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Line.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `line`
 *   - `id`
 *   - `displayName`
 * 	 - `email` 			  optional (has to be requested on the line developer dashboard)
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
	const url = uri.format(uri.parse(this._profileURL));

	this._oauth2.get(url, accessToken, function (err, body, res) {
		if (err)
			return done(new InternalOAuthError('Failed to fetch user profile', err));

		try {
			const json = JSON.parse(body);

			let profile = { provider: 'line' };
			profile.id = json.userId;
			profile.displayName = json.displayName;

			profile._raw = body;
			profile._json = json;

			done(null, profile);
		} catch (e) {
			done(e);
		}
	});
};

module.exports = Strategy;
