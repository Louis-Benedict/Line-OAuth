## Usage

### Setting Up a Service

Before utilizing passport-line-auth, you need to register a service with LINE. If you haven't already done so, you can create a new service at the [LINE Business Center](https://business.line.me/). Your service will receive a channel ID and channel secret, which are required for the strategy. Additionally, you'll need to configure a redirect URI that matches the route in your service.

### Configuring the Strategy

The LINE authentication strategy authenticates users through a LINE account and OAuth 2.0 tokens. When creating the strategy, provide the channel ID and secret obtained during service creation as options. The strategy also requires a `verify` callback, which receives the access token and optionally the refresh token, along with the `profile` containing the authenticated user's LINE profile. The `verify` callback must call `cb` to complete the authentication by providing a user.

```javascript
passport.use(
	new LineStrategy(
		{
			channelID: LINE_CHANNEL_ID,
			channelSecret: LINE_CHANNEL_SECRET,
			generateState: true, // Default is true
			callbackURL: 'http://localhost:3000/auth/line/callback',
		},
		function (accessToken, refreshToken, profile, cb) {
			User.findOrCreate({ lineId: profile.id }, function (err, user) {
				return cb(err, user);
			});
		}
	)
);
```
