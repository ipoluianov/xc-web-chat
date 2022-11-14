<template>
  <h1>{{ ttt }}</h1>
  <button @click="startPeer">Start</button>
  <button @click="stopPeer">Stop</button>
  <button @click="call">Call</button>
  <button @click="callClient">Call client</button>
</template>

<script>
import xchg from "@/components/xchg";
import base32 from "@/components/base32";
import makeXPeer from "./components/xpeer";

export default {
  data() {
    return {
      ttt: "HELLO",
    };
  },

  mounted() {
    this.peer = makeXPeer();
    this.clientPeer = makeXPeer();
  },

  methods: {
    async backgroundWorker() {
      try {
        var result = await this.peer.call(
          "#kpwwechavulhwyo6lbxgrijdtb4hc3wflt3yx6auo47von4r",
          "time",
          new ArrayBuffer(0)
        );
        var enc = new TextDecoder();
        this.ttt = enc.decode(result);
        console.log("FINAL RESULT:", this.ttt);
      } catch (ex) {
        console.log("Call exception:", ex);
      }
    },
    startPeer() {
      this.peer.start();
      this.clientPeer.start();
    },
    async call() {
      this.timer = window.setInterval(this.backgroundWorker, 200, this);
    },
    async callClient() {
      try {
        var result = await this.clientPeer.call(
          this.peer.localAddress,
          "time",
          new ArrayBuffer(0)
        );
        var enc = new TextDecoder();
        this.ttt = enc.decode(result);
        console.log("-=FINAL RESULT=-:", this.ttt);
      } catch (ex) {
        console.log("Call exception:", ex);
      }
    },
    stopPeer() {
      this.peer.stop();
    },
  },
};
</script>

<style>
</style>
