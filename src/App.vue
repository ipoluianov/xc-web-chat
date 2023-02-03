<template>
  <div style="display: flex; flex-direction: column; align-items: center; align-content: space-between;">
      <ChatServer style="min-height: 30vh; max-height: 30vh; min-width: 400pt; th: 400pt;" @started="onStarted"></ChatServer>
      <MessagerForm style="min-height: 60vh; max-height: 60vh; min-width: 400pt; max-width: 400pt;" ref="messager"></MessagerForm>
  </div>
</template>
<script>
import MessagerForm from "./components/MessagerForm.vue";
import ChatServer from "./components/ChatServer.vue";

export default {
  name: "app",
  components: {
    MessagerForm,
    ChatServer,
  },
  data() {
    return {};
  },

  mounted() {},

  methods: {
    onStarted(serverAddress) {
      console.log("HELLO", serverAddress);
      this.$refs.messager.setServerAddress(serverAddress);
    },
  },
};
</script>

<style>
  
</style>
