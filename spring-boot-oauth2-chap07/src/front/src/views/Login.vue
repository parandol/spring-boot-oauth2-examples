<template>
  <div class="login-box">
    <div class="login-background"></div>
    <div class="login-contents">
      <div class="login-title">
        <img class="client-icon" :src="client.icon">
        <h1>{{ client.name }}</h1>
        <div class="login-desc">
          {{ client.desc }}
        </div>
        <div class="login-authorization">
          <span v-if="client.authorization.length > 0">요청권한 : </span>
          <span :key="auth.name" v-for="(auth, index) in client.authorization">
            <span v-if="index > 0">, {{ auth }}</span>
            <span v-else>{{ auth }}</span>
          </span>
        </div>
        <div class="login-failure" v-if="isFailurePage">
          <span>Failure : </span>
          <span>
            유효한 사용자를 찾을 수 없습니다.
          </span>
        </div>
      </div>
      <div style="position:relative;height:280px;">
      <transition name="slide-fade">
      <div class="login-form" v-if="!showInputs">
        <template v-for="(user, index) in users">
          <div :key="user.userid" v-if="index < 2 && user.userid && user.userid != ''" class="user-element" @click="showInputForm(user);">
            <img class="user-icon" :src="user.icon" v-if="user.icon && user.icon != ''">
            <img class="user-icon" src="https://cdn.patchcdn.com/assets/layout/contribute/user-default.png" v-else>
            <span>{{ user.name }}</span>
          </div>
        </template>
        <div class="user-element unlisted" @click="showInputForm(null);">
          <img class="user-icon" src="https://cdn.patchcdn.com/assets/layout/contribute/user-default.png">
          다른 id 사용
        </div>
        <div class="login-buttons">
          <!--
          <button class="button-action">Next</button>
          <button class="button-action" @click.stop.prevent="addUser(1);">Add1</button>
          <button class="button-action" @click.stop.prevent="addUser(2);">Add2</button>
          <button class="button-action" @click.stop.prevent="addUser(3);">Add3</button>
          -->
        </div>
      </div>
      </transition>
      <transition name="slide-fade">
      <div class="login-inputs" v-if="showInputs">
        <form action="/login" method="post">
          <div v-if="selectUser != null">
            <img class="user-icon big" :src="selectUser.icon" v-if="selectUser.icon && selectUser.icon != ''">
            <img class="user-icon big" src="https://cdn.patchcdn.com/assets/layout/contribute/user-default.png" v-else>
            <input type="hidden" name="username" :value="username" />
            <br />
            {{ selectUser.name }}
            <label-input type="password" name="password" icon="unlock-alt" :value.sync="password">
              Password
            </label-input>
          </div>
          <div v-else>
            <label-input type="text" name="username" icon="user" :value.sync="username">
              User Id
            </label-input>
            <label-input type="password" name="password" icon="unlock-alt" :value.sync="password">
              Password
            </label-input>
          </div>
          <div class="login-buttons">
            <button class="button-action" @click.stop.prevent="hideInputForm();">Back</button>
            <button class="button-action" @click.stop.prevent="login();">Login</button>
          </div>
        </form>
      </div>
      </transition>
      </div>
      <!--
      <div id="nav">
        <router-link to="/">Home</router-link> |
        <router-link to="/about">About</router-link>
      </div>
      -->
      <div class="login-link">
        <div class="login-link-left"><router-link to="/forgot">Forgot password?</router-link></div>
        <div class="login-link-right"><router-link to="/signup">Sign up</router-link></div>
      </div>
    </div>
  </div>
</template>

<script>
// @ is an alias to /src
import HelloWorld from '@/components/HelloWorld.vue'
import LabelInput from '@/components/LabelInput.vue'
const axios = require('axios');

export default {
  name: 'home',
  components: {
    HelloWorld,
    LabelInput,
  },
  created : function() {
    let href = window.location.href;
    if(href.indexOf("?failure") >= 0) this.isFailurePage = true;
//     let uri = window.location.href.split('?');
//     if (uri.length == 2) {
//       let vars = uri[1].split('&');
//       let getVars = {};
//       let tmp = '';
//       vars.forEach(function(v) {
//         tmp = v.split('=');
//         if(tmp[0] == "failure") this.isFailurePage = true;
// //        if(tmp.length == 2)
// //        getVars[tmp[0]] = tmp[1];
//       });
// //      console.log(getVars);
//       // do 
//     }
  },
  computed: {
    users : function() {
      return this.$store.getters.getUsers;
    }
  },
  data : function() {
    return {
      username : "",
      password : "",
      /*
      users : [{
        icon: "https://image.flaticon.com/icons/png/512/164/164846.png",
        userid : "user1",
        name : "User 1"
      },
      {
        icon: "https://encrypted-tbn0.gstatic.com/images?q=tbn%3AANd9GcTt8L_upvY7RsbvSkrP7suu8NycEv-Fx-Uqgjc7kCne4wkSC5F0",
        userid : "user2",
        name : "User 2"
      },
      {
        icon: "https://www.clipartwiki.com/clipimg/detail/247-2475923_child-icon-child-emoji.png",
        userid : "user3",
        name : "User 3"
      }
      ],
      */
     
      // users : this.$store.state.users,
      client: {
        icon : "https://library.kissclipart.com/20191016/rqe/kissclipart-child-icon-happiness-icon-family-icon-4509ca3f41157322.png",
        name : "Client",
        desc : "Description...",
        authorization : [
          "read_profile",
          "write_article",
          "read_username",
          "read_email"
        ]
      },
      showInputs: false,
      selectUser: null,
      isFailurePage: false,
    }
  },
  methods: {
    addUser: function(index) {
      const users = [{
        icon: "https://image.flaticon.com/icons/png/512/164/164846.png",
        userid : "user1",
        name : "User 1"
      },
      {
        icon: "https://encrypted-tbn0.gstatic.com/images?q=tbn%3AANd9GcTt8L_upvY7RsbvSkrP7suu8NycEv-Fx-Uqgjc7kCne4wkSC5F0",
        userid : "user2",
        name : "User 2"
      },
      {
        icon: "https://www.clipartwiki.com/clipimg/detail/247-2475923_child-icon-child-emoji.png",
        userid : "user3",
        name : "User 3"
      }
      ];

      if(index > 0) {
        this.$store.dispatch("addUser", users[index -1 ]);
      }
    },
    showInputForm : function(user) {
      if(user != null) {
        //console.log(user);
        this.selectUser = user;
        this.username = user.userid;
        this.password = "";
      }
      this.showInputs = true;
    },
    hideInputForm : function() {
      // console.log("hide");
      this.showInputs = false;
      this.selectUser = null;
      this.username = "";
      this.password = "";
    },
    load: function() {
      axios.get("/auth/client", {
        params: {
        },
        timeout: 1000
      })
      .then( res => {
        // console.log(res)
        // console.log(res.data)
        if(res.data) {
          const data = res.data;
          if(data.code == "200") {
            this.client = res.data;
          } else {
            this.client = {
              icon: "https://tistory4.daumcdn.net/tistory/3410306/attach/97e22f962436482399d633524b87a6a6",
              name : "Error",
              desc : data.message,
              authorization: []
            };
          }
        }
      })
      .catch(
          error => {
            console.log("Error : " + error);
            //console.log("Data가 없습니다.");
          }
      );
    },
    login: function() {
      console.log(this.username + " : " + this.password);

      let form = new FormData();
      form.append('username', this.username);
      form.append('password',this.password);

      axios.post("/login", form)
      .then( res => {
        console.log(res)
        console.log(res.data)
        
        if(res.data) {
          const data = res.data;
          if(data.success == true) {
            this.isFailurePage = false;
            if(data.username && data.name) {
              const user = {
                userid : data.username,
                name : data.name,
                icon : data.icon,
              }
              this.$store.dispatch("addUser", user).then(() => {
                window.location.href = data.returnUrl;
              });
            } else {
              window.location.href = data.returnUrl;
            }
          } else {
            this.isFailurePage = true;
          }
        }
      })
      .catch(
          error => {
            // console.log(error)
            console.log("Error : " + error);
            //console.log("Data가 없습니다.");
          }
      );
    }
  },
  mounted : function() {
    this.load();
  }
}
</script>

<style scoped>
/* 애니메이션 진입 및 진출은 다른 지속 시간 및  */
/* 타이밍 기능을 사용할 수 있습니다. */
.slide-fade-enter-active {
  transition: all .5s ease;
}
.slide-fade-leave-active {
  transition: all .5s cubic-bezier(1.0, 0.5, 0.8, 1.0);
}
.slide-fade-enter, .slide-fade-leave-to {
  transform: translateX(260px);
  opacity: 0;
}

.login-authorization, .login-failure {
  font-style: italic;
  font-size: 0.9em;
  padding: 10px;
}
.login-failure {
  color: #ff0000;
}
.login-buttons {
  margin: 10px;
}
.login-desc {
  font-style: italic;
  font-size: 0.9em;
  padding: 10px;
}
.button-action {
    padding: 10px 25px;
    margin: 0 10px;
    background-color: #000000;
    color: #ffffff;
    outline: none;
    border: none;
    letter-spacing: 1px;
    text-transform: uppercase;
    cursor: pointer;
    border-radius: 20px;
    transition: 0.3s all;
    -webkit-transition: 0.3s all;
    -o-transition: 0.3s all;
    -moz-transition: 0.3s all;
    -ms-transition: 0.3s all;
}
.button-action:hover {
    box-shadow: 0px 0px 8px 0px #000000;
}
.login-title {
  height:280px;
}
.login-title h1 {
  margin: 0;
}
.login-link {
  display: flex;
  flex-wrap: wrap;
  padding: 0 5%;
}
.login-link-left {
  box-sizing: border-box;
  text-align: left;
  flex-basis: 50%;
}
.login-link-right {
  text-align: right;
  flex-basis: 50%;
}
.client-icon {
  width: 100px;
  height: 100px;
  border: 1px dashed #aaaaaa;
  border-radius: 50px;
  background-color: #ffffff;
  margin: 30px 10px 0 10px;
}
.user-icon {
  width: 40px;
  height: 40px;
  margin: 5px;
  vertical-align: middle;
  border-radius: 20px;
  border: 1px dashed #aaaaaa;
}
.user-icon.big {
  width: 60px;
  height: 60px;
  margin: 5px;
  border-radius: 40px;
}
.login-wrap {
  position: relative;
}

.login-background {
  z-index: 10;
  position:absolute;
  transform-origin: top left;
  transform: rotate(-20deg);
  width: 200%;
  height: 100%;
  left: 0;
  top: 20%;
  /* border: 1px solid #000000; */
  margin-left: -30%;
  margin-top: 65%;
  /* background-image: linear-gradient(to bottom right, #ffffff , #dddddd); */
  background-color: #ffffff;
}

.login-contents {
  position:absolute;
  z-index: 100;
  width: 100%;
  height: 100%;
}
.login-form, .login-inputs {
  position: absolute;
  width: 300px;
  padding: 10px 15%;
}
.user-element {
  text-align: left;
  margin: 0.3em 0;
  border: 1px solid #bbbbbb;
  border-radius:6px;
  padding: 0;
  /* transform: rotate(-20deg); */
  /* display:none; */
  cursor: pointer;
}
.user-element:hover {
    box-shadow: 0px 0px 8px 0px #bbbbbb;
}
.login-box {
  position:absolute;
  width: 420px;
  height: 600px;
  left:50%;
  top: 50%;
  margin-left: -210px;
  margin-top: -300px;
  border: 1px solid #cccccc;
  border-radius: 3px;
  overflow: hidden;
  background-image: linear-gradient(to bottom right, #ffffff, #e8e8e8);
  box-shadow: 0px 0px 10px 1px #cccccc;
}

@media (max-width: 400px) {
  .login-box {
    width: 300px;
    height: 300px;
    margin-left: -150px;
    margin-top: -150px;
  }
}

@media (max-width: 300px) {
  .login-box {
    width: 200px;
    height: 200px;
    margin-left: -100px;
    margin-top: -100px;
  }
}

#nav {
  padding: 30px;
}

#nav a {
  font-weight: bold;
  color: #2c3e50;
}

#nav a.router-link-exact-active {
  color: #42b983;
}
</style>