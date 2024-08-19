
# Oauth 2.0 - DPoP

Oauth 2.0 demonstrating Proof of Posession.

Implementation based on the research paper: https://datatracker.ietf.org/doc/html/rfc9449
and JS talk: https://www.youtube.com/watch?v=o9829nSzpEc&t=1s

## How DPoP works?

![Dpopflow](https://github.com/user-attachments/assets/98ad8a06-068a-4256-b945-85c9bf8aa58a)
image credit: https://developer.okta.com/docs/guides/dpop/nonoktaresourceserver/main/



## API Reference

#### Get authorisation code from authorization server

```http
  GET /authorize
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `dpop HEADER` | `string` | **Required**. DPOP header token |
| `client_id` | `string` | **Required**. client_id |
| `redirect_uri` | `string` | **Required**. redirect_uri |
| `scope` | `string` | **Required**. scope |

#### Get access token from authorization server

```http
  POST /token
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `grant_type` | `string` | **Required**. default 'authorization' |
| `code` | `string` | **Required**. code fetch from /authorize |
| `client_id` | `string` | **Required**. client_id |
| `dpop HEADER` | `string` | **Required**. DPOP header token |

#### Access protected route from resource server

```http
  GET /protected-resource
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `authorization`      | `string` | **Required**. access token(/token(auth server))
| `dpop HEADER` | `string` | **Required**. DPOP header token |


## Roadmap

- Dockerise the entire mono repo

- compose containers to run on aws infra.

- use lightweight db to store tokenmaps from auth/resource server


## Demo

![client](https://github.com/user-attachments/assets/80e4ca4a-c727-4cd5-9949-e7fbffd23d86)


## Run Locally

Clone the project

```bash
  git clone https://github.com/rakeshsenapathi/oauth-dpop-monorepo.git
```

Go to the project directory

```bash
  cd oauth-dpop-monorepo
```

Install dependencies

```bash
  pnpm install
```

run dev task in the monorepo

```bash
  pnpm turbo run dev
```

