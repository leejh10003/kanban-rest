var jwt = require('jsonwebtoken');
var fs = require('fs');
const privateKey = fs.readFileSync('./private.pem');
const publicKey = fs.readFileSync('./public.pem')
const Koa = require('koa');
const KoaRouter = require('koa-router');
const BodyParser = require('koa-bodyparser');
const cors = require('@koa/cors');
const axios = require('axios');
require('dotenv').config()
const { CLIENT_ID, CLIENT_SECRET } = process.env;
const urlencode = require('urlencode');
var pgp = require('pg-promise')({
	error(err, e) {
		if (e.cn) {
			console.log(cn)
		}

		if (e.query) {
			console.log(e.query)
			if (e.params) {
				console.log(e.params)
			}
		}

		if (e.ctx) {
			console.log(e.ctx)
		}
	}
});
var connectionString = `postgres://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:5432/${process.env.DB_DATABASE}`;
var db = pgp(connectionString);
function domainCheck(origin){
	if (['http://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com', 'https://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com', 'http://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com/', 'https://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com/']){
		return origin;
	} else {
		throw new Error(`Origin not match: ${origin}`);
	}
}
const app = new Koa();
app.proxy = true;
const router = new KoaRouter();
app.use(BodyParser());
router.options('naverSigninPreflight', '/login/naver', async (ctx) => {
	console.log(ctx.request.header);
	ctx.set('Access-Control-Allow-Origin', `${domainCheck(ctx.request.header.referer || ctx.request.header.origin)}`);
	ctx.set('Access-Control-Allow-Headers', 'Access-Control-Allow-Origin, Content-Type, Authorization');
	ctx.set('Access-Control-Allow-Credentials', true);
	ctx.response.status = 200;
})
router.post('naverSignin', '/login/naver', async (ctx) => {
	const { code, state, redirectURI } = ctx.request.body;
	console.log('Naver default imfornation code: ', code, ' state: ', state);
  const baseURL = `https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&client_id=${urlencode(CLIENT_ID)}&client_secret=${urlencode(CLIENT_SECRET)}&redirect_uri=${urlencode(redirectURI)}&code=${urlencode(code)}&state=${urlencode(state)}`;
	const token = axios.create({
    baseURL,
    timeout: 3000,
    headers: {
      'X-Naver-Client-Id': CLIENT_ID,
      'X-Naver-Client-Secret': CLIENT_SECRET
    }
  });
  const { data: { access_token } } = await token.get();
  const info = axios.create({
    baseURL: 'https://openapi.naver.com/v1/nid/me',
    headers: {'Authorization': `Bearer ${access_token}`}
  })
  const { data: { response: { id, nickname, profile_image, email, name } } } = await info.get();
  console.log(id, nickname, profile_image, email, name)
  const user = (await db.query("SELECT * FROM user WHERE naver_id = ${id}", {
    id
  }))
  if (user?.length > 0){
    const uerId = user?.[0]?.id
    const payload = {
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-default-role": "user",
        "x-hasura-dib-user-id": uerId.toString(),
      },
    }
    const refresh = {
      id: uerId,
    }
    const refreshToken = jwt.sign(refresh, privateKey, {
      algorithm: 'RS256'
    });
    const accessToken = jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      expiresIn: "1h"
    });
    await db.query("UPDATE user SET refreshToken = ${refreshToken} WHERE id = ${userId}", {
      refreshToken,
      userId
    })
    ctx.cookies.set('refreshToken', null, {
      httpOnly: true,
      secure: true,
      domain: 'ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com',
      expires: new Date(1000 * 60 * 60 * 9 + Date.now())
    });
    ctx.response.body = {
      token: accessToken,
      newUser: false
    };
  }
});
router.options('refreshPreflight', '/refresh', async (ctx) => {
	console.log(ctx.request.header);
	ctx.set('Access-Control-Allow-Origin', `${domainCheck(ctx.request.header.referer || ctx.request.header.origin)}`);
	ctx.set('Access-Control-Allow-Headers', 'Access-Control-Allow-Origin, Content-Type, Authorization');
	ctx.set('Access-Control-Allow-Credentials', true);
	ctx.response.status = 200;
})
router.post('refresh', '/refresh', async (ctx) => {
	const refreshToken = ctx.cookies.get('refreshToken');
	const { kind, adminId, partnerId, iat } = jwt.verify(refreshToken, publicKey, {
		algorithms: ["RS256"]
	});
	console.log(kind, adminId, partnerId, iat)
	try {
		const inDbRefreshToken = (await db.query(`SELECT refresh_token FROM admin WHERE id = ${adminId} AND product_partner_id = ${partnerId} AND enabled = true`))[0].refresh_token;
		if (inDbRefreshToken === refreshToken) {
			console.log("available crm refresh token: ", inDbRefreshToken, refreshToken);
			const token = {
				"https://hasura.io/jwt/claims": {
					"x-hasura-allowed-roles": kind,
					"x-hasura-default-role": kind[0],
					"x-hasura-admin-id": adminId.toString(),
					"x-hasura-partner-id": partnerId
				},
			}
			ctx.response.body = JSON.stringify({
				'success': true,
				'token': jwt.sign(token, privateKey, {
					algorithm: 'RS256',
					expiresIn: "2m"
				})
			});
		} else {
			ctx.response.body = JSON.stringify({
				'success': false
			});
			ctx.response.status = 500;
		}
	} catch {
		ctx.response.body = JSON.stringify({
			'success': false
		});
		ctx.response.status = 500;
	}
	ctx.set('Access-Control-Allow-Origin', `${domainCheck(ctx.request.header.referer || ctx.request.header.origin)}`);
	ctx.set('Access-Control-Allow-Credentials', 'true');
});
app.use(router.routes())
	.use(router.allowedMethods())
	.use(cors({
		credentials: true,
		exposeHeaders: ['Access-Control-Allow-Credentials', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin', 'Set-Cookie', 'X-Forwarded-Proto']
	})).listen(process.env.PORT, () => console.log('Running on port 3000'));
