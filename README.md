

# Directus Extension for Hasura JWTs
This Hook allows you to use claims from your Hasura JWT to set the `accountability` object in Directus during remote schema requests.

This works by having Hasura pass a `DIRECTUS_SECRET` in the header, in addition to forwarding all client headers, when making remote schema requests. 

When this hook sees the `DIRECTUS_SECRET` in the header, it will decode the payload of the forwarded Authorization header and use the Directus claims namespace to populate the `accounability` object for that session.

This allows you to use Hasura's Remote Schema feature while still managing user permissions within Directus. This also keeps the Activity Log in tact.

#### Note: This is a work in progress


# Flowchart
![alt text](https://github.com/clockradios/directus-hasura-authentication-extension/blob/main/flow.png?raw=true)
