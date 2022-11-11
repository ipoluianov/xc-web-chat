<template>
  <h1>{{ ttt }}</h1>
  <button @click="fetchData">123123</button>
  <button @click="generateKeyPair">Generate Key Pair</button>
</template>

<script>
import axios from "axios";
import xchg from "@/components/xchg";
import base32 from "@/components/base32";

export default {
  data() {
    return {
      ttt: "HELLO",
    };
  },
  methods: {
    async fetchData() {
      console.log("---");
      xchg.requestXchgrRead("#34lvkft6xkejalctgogx3ecuusmydmf6omkac3xnjn3emolg");
      console.log("---");
    },
    generateKeyPair() {
      xchg.test();
    },
  },
};
</script>

<style>
</style>
