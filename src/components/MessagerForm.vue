<template>
  <div class="mainContainer">
    <div class="header">XC-WEB-CHAT</div>
    <div class="localAddress">Chat Address</div>
    <div class="localAddress">{{ localAddress }}</div>
    <div><input v-model="remoteAddress" placeholder="Address" /></div>
    <div style="flex-grow: 1">
      <div>Result:</div>
      <li v-for="item in messages" :key="item.iasdd">
        {{ item }}
      </li>
    </div>
    <div style="display:flex; flex-direction: row;">
      <input style="flex-grow: 1; font-size: 16pt;" v-model="message" placeholder="Message" />
      <button @click="btnSend">Send</button>
    </div>
  </div>
</template>
  
  <script>
import xchg from "@/components/xchg";

export default {
  mounted() {
    this.peer = xchg.makeXPeer();
    this.peer.onCall = this.receivedCall;
    this.peer.start().then(() => {
      this.localAddress = this.peer.localAddress;
      //this.remoteAddress = this.peer.localAddress;
    });
    this.timer = window.setInterval(this.backgroundWorker, 1000, this);
  },

  beforeUnmount() {
    window.clearInterval(this.timer);
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
      if (this.remoteAddress.length < 1) {
        alert("No address");
        return;
      }

      await this.peer.call(
        this.remoteAddress,
        new TextEncoder().encode("").buffer,
        "send_message",
        new TextEncoder().encode(this.message).buffer
      );
    },
    setServerAddress(addr) {
      console.log("setServerAddress", addr);
      this.remoteAddress = addr;
      this.messages = [];
    },
    async backgroundWorker() {
      if (this.peer === undefined) {
        return;
      }
      if (this.remoteAddress.length < 1) {
        return;
      }
      let res = await this.peer.call(
        this.remoteAddress,
        new TextEncoder().encode("").buffer,
        "get_messages",
        new TextEncoder().encode(this.messages.length.toString()).buffer
      );
      let resString = new TextDecoder().decode(res);
      let resObj = JSON.parse(resString);
      for (let i = 0; i < resObj.length; i++) {
        let msg = resObj[i];
        if (msg.id == this.messages.length) {
          this.messages.push(msg.message);
        }
      }
      console.log("RES:", resObj);
    },
  },
};
</script>
  
<style>
.mainContainer {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  background-color: #eeeeee;
}
.header {
  text-align: center;
  padding: 10pt;
  margin: 0pt;
  margin-bottom: 10px;
  font-size: 14pt;
  font-family: Verdana, Geneva, Tahoma, sans-serif;
  background-color: #2b5278;
  color: #ffffff;
}
.localAddress {
  font-family: Verdana, Geneva, Tahoma, sans-serif;
  text-align: center;
  padding: 10pt;
}
</style>
  