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
const { CLIENT_ID, CLIENT_SECRET, ACCESS_KEY_ID, SECRET_ACCESS_KEY, S3_BUCKET_NAME } = process.env;
const urlencode = require('urlencode');
const multer = require("@koa/multer");
const upload = multer({
    storage: multer.memoryStorage()
});
const AWS = require("aws-sdk");
const FileType = require('file-type');
const s3 = new AWS.S3({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY
});
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
	console.log(origin)
	if (["http://test.jeontuk-11.link:8080", 'http://trello.jeontuk-11.link', 'https://trello.jeontuk-11.link', 'http://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com', 'https://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com', 'http://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com/', 'https://ec2-54-180-17-216.ap-northeast-2.compute.amazonaws.com/']){
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
  const user = (await db.query("SELECT * FROM public.user WHERE naver_id = ${id}", {
    id
  }))
  if (user?.length > 0){
    const userId = user?.[0]?.id
    const payload = {
			thumbnail: profile_image,
			name,
			email,
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-default-role": "user",
        "x-hasura-user-id": userId.toString(),
      },
    }
    const refresh = {
      id: userId,
    }
    const refreshToken = jwt.sign(refresh, privateKey, {
      algorithm: 'RS256'
    });
    const accessToken = jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      expiresIn: "1h"
    });
    await db.query("UPDATE public.user SET refresh_token = ${refreshToken} WHERE id = ${userId}", {
      refreshToken,
      userId
    })
    ctx.cookies.set('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      domain: 'trello.jeontuk-11.link',
      expires: new Date(1000 * 60 * 60 * 9 + Date.now())
    });
    ctx.response.body = {
      token: accessToken,
      newUser: false
    };
  } else {
		await db.tx(async (t) => {
			const newUser = await t.one("INSERT INTO public.user(thumbnail, naver_id, nickname, email, name) VALUES (${profile_image}, ${id}, ${nickname}, ${email}, ${name}) RETURNING id", {
				id,
				nickname,
				profile_image,
				email,
				name
			});
			const userId = newUser?.id
			const payload = {
				thumbnail: profile_image,
				name,
				email,
				"https://hasura.io/jwt/claims": {
					"x-hasura-allowed-roles": ["user"],
					"x-hasura-default-role": "user",
					"x-hasura-user-id": userId.toString(),
				},
			}
			const refresh = {
				id: userId,
			}
			const refreshToken = jwt.sign(refresh, privateKey, {
				algorithm: 'RS256'
			});
			const accessToken = jwt.sign(payload, privateKey, {
				algorithm: 'RS256',
				expiresIn: "1h"
			});
			await t.query("UPDATE public.user SET refresh_token = ${refreshToken} WHERE id = ${userId}", {
				refreshToken,
				userId
			})
			ctx.cookies.set('refreshToken', refreshToken, {
				httpOnly: true,
				secure: true,
				domain: 'trello.jeontuk-11.link',
				expires: new Date(1000 * 60 * 60 * 9 + Date.now())
			});
			ctx.response.body = {
				token: accessToken,
				newUser: true
			};
		});
	}
});
router.options('imagePreflight', '/image', async (ctx) => {
	console.log(ctx.request.header);
	ctx.set('Access-Control-Allow-Origin', `${domainCheck(ctx.request.header.referer || ctx.request.header.origin)}`);
	ctx.set('Access-Control-Allow-Headers', 'Access-Control-Allow-Origin, Content-Type, Authorization');
	ctx.set('Access-Control-Allow-Credentials', true);
	ctx.response.status = 200;
})
router.post('image', '/image', upload.fields([{
	name: 'file'
}]), async (ctx) => {
	const { authorization } = ctx.request.headers;
	const tokenPayload = jwt.verify(authorization.substring(7), publicKey, {
		algorithms: ["RS256"]
	})['https://hasura.io/jwt/claims'];
	const userId = parseInt(tokenPayload['x-hasura-dib-user-id']);
	try {
		console.log(ctx.request.files)
		if (!!(ctx.request.files) && (ctx.request.files.file.length > 0)){
			const uploads = ctx.request.files.file.map((file) => new Promise(async () => {
				const fileFromBUffer = await FileType.fromBuffer(file.buffer);
				const result = await s3.upload({
					Bucket: S3_BUCKET_NAME,
					ACL: 'public-read',
					Body: file.buffer,
					Key: `/${userId}/${Date.now()}.${fileFromBUffer.ext}`
				}).promise()
				return result;
			}));
			console.log(uploads)
			const uploadResults = await Promise.all(uploads);
			console.log(uploadResults)
			ctx.response.body = JSON.stringify(uploadResults);
			ctx.response.status = 200;
		} else {
			throw new Error();
		}
	} catch (e) {
		console.error(e)
		ctx.response.body = JSON.stringify({
			'success': false
		});
		ctx.response.status = 500;
	}
	ctx.set('Access-Control-Allow-Origin', `${domainCheck(ctx.request.header.referer || ctx.request.header.origin)}`);
	ctx.set('Access-Control-Allow-Credentials', 'true');
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
	const { id, iat } = jwt.verify(refreshToken, publicKey, {
		algorithms: ["RS256"]
	});
	console.log(id, iat)
	try {
		const user = await db.one("SELECT * FROM public.user WHERE id = ${id} AND refresh_token = ${refreshToken}", {
			id, refreshToken
		});
		console.log(user)
		const payload = {
			thumbnail: user.thumbnail,
			name: user.name,
			email: user.email,
			"https://hasura.io/jwt/claims": {
				"x-hasura-allowed-roles": ["user"],
				"x-hasura-default-role": "user",
				"x-hasura-user-id": id.toString(),
			},
		}
		ctx.response.body = JSON.stringify({
			'success': true,
			'token': jwt.sign(payload, privateKey, {
				algorithm: 'RS256',
				expiresIn: "1h"
			})
		});
	} catch (e) {
		console.error(e)
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
	})).listen(process.env.PORT, () => console.log(`Running on port ${process.env.PORT}`));
