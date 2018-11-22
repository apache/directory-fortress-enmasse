module.exports = {
  lintOnSave: false,

  devServer: {
    proxy: {
      '/fortress-rest': {
        target: 'http://localhost:7070',
        changeOrigin: true
      }
    }
  },

  baseUrl: '',
  productionSourceMap: false
}