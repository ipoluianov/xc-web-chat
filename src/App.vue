<template>
  <h1>{{ ttt }}</h1>
  <button @click="startPeer">Start</button>
  <button @click="stopPeer">Stop</button>
  <button @click="call">Call</button>
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
  },
  
  methods: {
    async backgroundWorker() {
      var result = await this.peer.call("#wl66natta5aj44ogb7bxtezre34sqhbwwwplx5l42h66mi34", "time", new ArrayBuffer(0));
      var enc = new TextDecoder();
      this.ttt = enc.decode(result);
      console.log("FINAL RESULT:", this.ttt);
      console.log("timer");
    },
    startPeer() {
      this.peer.start();
    },
    async call() {
      this.timer = window.setInterval(this.backgroundWorker, 200, this);
    },
    stopPeer() {
      this.peer.stop();
    },
  },
};
</script>

<style>
</style>
