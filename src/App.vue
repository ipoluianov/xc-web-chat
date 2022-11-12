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
    startPeer() {
      this.peer.start();
    },
    call() {
      this.peer.call("#psr2c7iy3nk4oclnz26qthlmevvc7njb3cnuoq3ly4ffdrhh", "");
    },
    stopPeer() {
      this.peer.stop();
    },
  },
};
</script>

<style>
</style>
