const { User } = require("../models/User");

const auth = (req, res, next) => {
  //인증처리
  //클라이언트 쿠키에서 토큰을 가져온다
  const token = req.cookies.x_auth;
  //token decode 하고 유저를 찾는다
  User.findByToken(token, (err, user) => {
    if (err) throw err;
    if (!user) return res.json({ isAuth: false, error: true });

    req.token = token;
    req.user = user;
    next();
  });
  //유저가 있으면 인증허가
  //유저가 없으면 인증불허
};

module.exports = { auth };
