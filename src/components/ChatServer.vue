<template>
  <div class="mainContainer">
    <div class="header">XC-WEB-SERVER</div>
    
      <div
        v-if="localAddress != ''"
        style="display: flex; flex-direction: row;"
      >
        <div class="localAddress">Address:</div>
        <input ref="address" v-model="localAddress" style="flex-grow: 1" />
        <button @click="copyText">Copy</button>
      </div>
    <div v-if="localAddress == ''">
      <button class="btnStart" @click="btnStart">Run</button>
    </div>
    <div>MS: {{ messages.length }}</div>
    <div>PF: {{ statProcessedFrames }}</div>
    <div>RD: {{ statR }}</div>
    <div>WR: {{ statW }}</div>
    <div>RT: {{ statCurrentRouters }}</div>
  </div>
</template>
    
    <script>
import xchg from "@/components/xchg";

export default {
  mounted() {
    this.timer = window.setInterval(this.backgroundWorker, 100, this);
  },

  beforeUnmount() {
    window.clearInterval(this.timer);
  },

  data() {
    return {
      localAddress: "",
      messages: [],
      statR: 0,
      statW: 0,
      statProcessedFrames: 0,
      statCurrentRouters: "",
    };
  },

  methods: {
    receivedCall(funcName, funcParameter) {
      if (funcName === "send_message") {
        this.messages.push(new TextDecoder().decode(funcParameter));
      }
      if (funcName === "get_messages") {
        let p = new TextDecoder().decode(funcParameter);
        let lastMessageId = Number(p);
        console.log(lastMessageId);

        let resultArray = [];
        for (let i = lastMessageId; i < this.messages.length; i++) {
          let msg = {
            id: i,
            message: this.messages[i],
          };
          resultArray.push(msg);
        }

        let jsonStr = JSON.stringify(resultArray);

        let res = new TextEncoder().encode(jsonStr).buffer;
        return res;
      }
      return funcParameter;
    },
    async btnStart() {
      this.peer = xchg.makeXPeer();
      this.peer.onCall = this.receivedCall;
      this.peer.start().then(() => {
        this.localAddress = this.peer.localAddress;
        this.$emit("started", this.peer.localAddress);
      });
    },
    backgroundWorker() {
      if (this.peer === undefined) {
        return;
      }
      this.statProcessedFrames = this.peer.stat.processedFrames;
      this.statR = this.peer.stat.R_count;
      this.statW = this.peer.stat.W_count;
      this.statCurrentRouters = this.peer.currentRouters();
    },
    copyText() {
      const element = this.$refs.address;
      element.select();
      element.setSelectionRange(0, 99999);
      navigator.clipboard.writeText(element.value);
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
  max-height: 200pt;
}
.header {
  text-align: center;
  padding: 3pt;
  margin: 0pt;
  margin-bottom: 3px;
  font-size: 14pt;
  font-family: Verdana, Geneva, Tahoma, sans-serif;
  background-color: #2b5278;
  color: #ffffff;
}
.localAddress {
  font-family: Verdana, Geneva, Tahoma, sans-serif;
  text-align: center;
  padding: 3pt;
}
.btnStart {
  padding: 3pt;
  margin: 3pt;
  min-width: 100pt;
  cursor: pointer;
}
</style>
    