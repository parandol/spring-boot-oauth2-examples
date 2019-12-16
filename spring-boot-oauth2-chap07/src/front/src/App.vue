<template>
  <div id="app">
    <div class="background-wrap">
      <div class="background-box"></div>
      <router-view/>
    </div>
  </div>
</template>

<script>
export default {
  data : function() {
    return {
    }
  },
}
</script>

<style>
html, body {
    margin: 0;
    height: 100%;
    overflow: hidden;
    font-size: 10pt;
}

body {
  display: flex;
  height:100%;
  background-image: linear-gradient(to bottom left, #ffffff, #e8e8e8);
}
.background-wrap {
  position:relative;
  height:100%;

}
.background-box {
  position:absolute;
  transform-origin: top left;
  transform: rotate(20deg);
  width: 500%;
  height: 80%;
  left: 0;
  top: 30%;
  /* border: 1px solid #000000; */
  margin-left: -30%;
  margin-top: -15%;
  background-image: linear-gradient(to bottom right, #ffffff , #dddddd);
}
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  width:100%;
  height:100%;
}

</style>
