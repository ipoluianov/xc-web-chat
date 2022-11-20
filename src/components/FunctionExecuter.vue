<template>
  <div>
    <div>Executer</div>
    <div><input v-model="address" placeholder="Address" /></div>
    <div><input v-model="authData" placeholder="Auth Data" /></div>
    <div><input v-model="func" placeholder="Function" /></div>
    <div><button @click="btnExecute">Run</button></div>
    <div>Result:</div>
    <div>{{result}}</div>
  </div>
</template>

<script>
import xchg from "@/components/xchg";
import makeXchgSimpleServer from "@/components/xchg_simple_server.js"

export default {
  mounted() {
    this.server = makeXchgSimpleServer();
    this.clientPeer = xchg.makeXPeer();
    this.clientPeer.start();
  },

  data() {
    return {
      address: "#pem53ka2436w5bqgeaaqjud5uki4i7msbphqdezjehkz6ghp",
      authData: "KF5OFPKMG72Y3GXXSB6T43KIXB7QHEEXUSMEYXYKLRDCQRWN",
      func: "service_info",
      result: "-",
    };
  },

  methods: {
    async btnExecute() {
      console.log("EXECUTE");
      try {
        var res = await this.clientPeer.call(
          this.address,
          new TextEncoder().encode(this.authData).buffer,
          this.func,
          new TextEncoder().encode("{}").buffer,
        );
        console.log(res);
        this.result = new TextDecoder().decode(res);
      } catch (ex) {
        console.log("ERROR:", ex);
        this.result = "Error:" + ex.toString();
      }
    },
  },
};
</script>

<style>
</style>
