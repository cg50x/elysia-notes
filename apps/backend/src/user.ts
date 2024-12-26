import { Elysia, t } from "elysia";

export const userService = new Elysia({ name: "user/service" })
  .state({
    user: {} as Record<string, string>,
    session: {} as Record<string, string>
  })
  .model({
    signIn: t.Object({
      username: t.String({ minLength: 1 }),
      password: t.String({ minLength: 8 })
    }),
    session: t.Cookie({
      token: t.Number()
    }, {
      secrets: "seia"
    })
  }).model({
    optionalSession: t.Optional(t.Cookie({
      token: t.Number()
    }, {
      secrets: "seia"
    }))
  })
  .macro({
    isSignIn(enabled: boolean) {
      if (!enabled) { 
        return;
      }
      return {
        beforeHandle({ error, cookie: { token }, store: { session } }) {
          if (!token.value) {
            return error(401, {
              success: false,
              message: "Unauthorized"
            });
          }
          const username = session[token.value];
          if (!username) {
            return error(401, {
              success: false,
              message: "Unauthorized"
            });
          }
        }
      };
    }
  });

export const getUserId = new Elysia()
  .use(userService)
  .guard({
    isSignIn: true,
    cookie: "session"
  })
  .resolve(({ store: { session }, cookie: { token }}) => ({
    username: session[token.value]
  })).as("plugin");

export const user = new Elysia({ prefix: "/user" })
  .use(userService)
  .put(
    "/sign-up", async ({ body: { username, password }, store, error }) => {
      if (store.user[username]) {
        return error(400, {
          success: false,
          message: "Username already exists"
        });
      }
      store.user[username] = await Bun.password.hash(password);
      return {
        success: true,
        message: "User created"
      };
    }, {
      body: "signIn"
    })
  .post("sign-in", async ({ body: { username, password }, store: { user, session }, cookie: { token }, error }) => {
    if (!user[username] || !(await Bun.password.verify(password, user[username]))) {
      return error(401, {
        success: false,
        message: "Invalid username or password"
      });
    }
    const key = crypto.getRandomValues(new Uint8Array(1))[0];
    session[key] = username;
    token.value = key;
    return {
      success: true,
      message: `Signed in as ${username}`
    };
  }, {
    body: "signIn",
    cookie: "optionalSession"
  })
  .get("/sign-out", ({ cookie: { token } }) => {
    token.remove();
    return {
      success: true,
      message: "Signed out"
    };
  }, {
    cookie: "optionalSession"
  })
  .use(getUserId)
  .get("/profile", ({ cookie: { token }, store: { session }, error }) => {
    const username = session[token.value];
    if (!username) {
      return error(401, {
        success: false,
        message: "Unauthorized"
      });
    }
    return {
      success: true,
      username
    };
  }, {
    isSignIn: true,
    cookie: "session"
  });
