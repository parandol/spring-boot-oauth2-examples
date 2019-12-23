import Vue from 'vue'
import Vuex from 'vuex'
import createPersistedState from "vuex-persistedstate";

Vue.use(Vuex)

export default new Vuex.Store({
  state: {
    users: []
  },
  mutations: {
    addUser: function (state, payload) {
      // removeUser(state, payload);
      return state.users.unshift(payload);
    },
    removeUser: function (state, payload) {
      let index = -1;
      for(let idx = 0; idx < state.users.length; idx++) {
        const item = state.users[idx];
        if(item.userid === payload.userid) {
          index = idx;
          break;
        }
      };
      return (index >= 0) ? state.users.splice(index, 1) : state.users;
    },
  },
  actions: {
    addUser: function (context, payload) {
      this.commit("removeUser", payload);
      this.commit("addUser", payload);
    },
    removeUser: function (context, payload) {
      this.commit("removeUser", payload);
    },
  },
  modules: {
  },
  getters: {
    getUsers : function(state) {
      return state.users;
    }
  },
  plugins: [createPersistedState()]
})
