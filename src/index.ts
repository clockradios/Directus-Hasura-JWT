import { defineHook } from '@directus/extensions-sdk';
import * as fs from 'fs';
import jwt from 'jsonwebtoken'

export default defineHook(({ filter }) => {
	filter('authenticate', async (input: any, meta, { accountability }) => {

		// Not sure if this is necessary 
		const hasura_role = meta?.req?.['x-hasura-role']
		if (hasura_role === "public") {
			return {
				...input,
				role: "public"
			}
		}

		// I'm not sure if I can use env vars in Directus Hooks
		const secret = process.env.DIRECTUS_HASURA_SECRET

		// Data from the authentication payload
		const token = meta?.req?.token
		const meta_secret = meta?.req?.directus_hasura_secret
		const operation = meta?.req?.body?.operationName

		// If we are logging in from Hasura (Remote Schema)
		// then set the "accountability" with the user data
		// in the Hasura/Auth0 JWT.
		// Otherwise use the normal auth flow.
		// This allows directus dashboard logins to still work

		if (secret === meta_secret) {

			// If Hasura is trying to introspect, give it admin perms
			if (operation === "IntrospectionQuery") {
				const accountability = {
					...input,
					role: "admin",
					admin: true,
					app: false
				};
				return accountability
			}

			// If a JWT token has been passed, parse the user data
			if (token) {
				// This can just be a JWT decode instead of verify
				// since we have the hasura -> directus secret 

				const decoded: any = jwt.decode(token)
				const accountability = {
					...input,
					user: decoded?.directus?.user_uuid,
					role: decoded?.directus?.user_role,
					admin: decoded?.directus?.is_admin || false,
					app: decoded?.directus?.is_app_user || false
				};
				return accountability

				// We could also validate the JWT against the Cert here
				// This might slow things down too much and we have the secret

				const cert = fs.readFileSync('public.pem');  // get public key
				return jwt.verify(token, cert, function (err: any, decoded: any) {
					if (err) {
						console.log(err)
						return
					}
					const accountability = {
						...input,
						user: decoded.directus.user_uuid,
						role: decoded.user_role || "public",
						admin: decoded.directus.is_admin || false,
						app: decoded.directus.is_app_user || false
					};
					return accountability
				});
			}
		}
	});
});
