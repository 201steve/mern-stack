const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const saltRounds = 10;
const jwt = require("jsonwebtoken");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50,
  },
  email: {
    type: String,
    trim: true,
    unique: 1,
  },
  password: {
    type: String,
    minlength: 5,
  },
  lastName: {
    type: String,
    maxlength: 50,
  },
  role: {
    type: Number,
    default: 0,
  },
  image: String,
  token: {
    type: String,
  },
  tokenExp: {
    type: Number,
  },
});

userSchema.pre("save", function (next) {
  const user = this;

  if (user.isModified("password")) {
    //비밀번호 암호화 bcrypt
    bcrypt.genSalt(saltRounds, function (err, salt) {
      if (err) return next(err);

      bcrypt.hash(user.password, salt, function (err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();
        // Store hash in your password DB.
      });
    });
  } else {
    next();
  }
});

userSchema.methods.comparePassword = function (planPassword, cb) {
  //plainPassword 1234567 === 암호화된 비밀번호 $2a$10$ui98Uv6gGLmZ2bY8JAFkJ.3aYuSSmI7ELM2SlmaIuSw2hQwWoobZe
  bcrypt.compare(planPassword, this.password, function (err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

userSchema.methods.generateToken = function (cb) {
  //jsonwebtoken을 이용해서 token 생성하기

  const user = this;
  const token = jwt.sign(user._id.toHexString(), "secreatToken");
  user.token = token;
  user.save(function (err, user) {
    if (err) return cb(err);
    cb(null, user);
  });
};

userSchema.statics.findByToken = function (token, cb) {
  const user = this;

  //token decode
  jwt.verify(token, "secreatToken", function (err, decoded) {
    //유저 아이디를 이용해서 유저를 찾은 다음에
    //클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인

    user.findOne(
      {
        _id: decoded,
        token: token,
      },
      function (err, user) {
        if (err) return cb(err);
        cb(null, user);
      }
    );
  });
};

const User = mongoose.model("User", userSchema);

module.exports = { User };
