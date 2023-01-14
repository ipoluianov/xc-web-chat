<template>
  <div>
    <div>Messager</div>
    <div>Local Address: {{ localAddress }}</div>
    <div><input v-model="remoteAddress" placeholder="Address" /></div>
    <div><input v-model="message" placeholder="Message" /></div>
    <div><button @click="btnSend">Run</button></div>
    <div>Result:</div>
    <div>
        <li v-for="(item) in messages" :key="item.iasdd">
            {{ item }}
        </li>
    </div>
  </div>
</template>
  
  <script>
import xchg from "@/components/xchg";

export default {
  mounted() {
    this.peer = xchg.makeXPeer();
    this.peer.onCall = this.receivedCall
    this.peer.start().then(() => {
      this.localAddress = this.peer.localAddress;
      this.remoteAddress = this.peer.localAddress;
    });
  },

  data() {
    return {
      localAddress: "",
      remoteAddress: "",
      message: "",
      messages: [],
    };
  },

  methods: {
    receivedCall(funcName, funcParameter) {
        this.messages.push(new TextDecoder().decode(funcParameter));
      return funcParameter;
    },
    async btnSend() {
        await this.peer.call(
          this.remoteAddress,
          new TextEncoder().encode("").buffer,
          "send_message",
          new TextEncoder().encode(this.message).buffer
        );
    },
  },
};
</script>
  
<style>
</style>
  