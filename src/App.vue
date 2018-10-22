<template>
  <div>
    <router-link to="/user">Go to User</router-link>

    <router-view/>

    <!--
    <MyFooter></MyFooter>
    -->
  </div>
</template>

<script>
  //import MyHeader from '@/components/Header'
  //import MyFooter from '@/components/Footer'

  export default {
    name: 'App',
    components: {
      //MyHeader,
      //MyFooter
    }
  }
</script>
