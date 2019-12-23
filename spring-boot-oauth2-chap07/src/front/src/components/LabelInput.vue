<template>
  <div class="label-input">
    <div class="label">
      <font-awesome-icon :icon="icon" />
    </div>
    <div class="input">
      <input :type="type"
        :name="name"
        :value="value"
        @input="$emit('update:value', $event.target.value)"
      />
    </div>
    <!--
    <slot></slot>
    -->
  </div>
</template>

<script>
export default {
  name: 'LabelInput',
  props: {
    icon: String,
    name: String,
    type: String,
    value: String
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
.label-input {
  margin: 5px 10px;
  border: 1px solid #cccccc;
  border-radius: 10px;
  display: flex;
  flex-wrap: wrap;
}

.label-input .label {
  box-sizing: border-box;
  border-right: 1px solid #cccccc;
  flex-basis: 30px;
  padding: 10px;
  margin: 0;
}

.label-input svg {
  font-size: 16px;
  color: #00A1A7;
}
.label-input .input {
  box-sizing: border-box;
  height: 36px;
  padding: 0;
  text-align:left;
  flex-basis: calc(100% - 36px);
}
.label-input input {
  height: 27px;
  width: calc(100% - 15px);
  margin: 5px;
  border: 0;
  background: #ffffff;
}
</style>
