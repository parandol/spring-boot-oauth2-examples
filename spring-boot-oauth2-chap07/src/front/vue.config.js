module.exports = {
    devServer: {
        proxy: {
          '/login': {
              target: 'http://localhost:9090',
              changeOrigin: true,
//                pathRewrite: {
//                    '^/data': ''
//                }
          },
          '/auth': {
              target: 'http://localhost:9090',
              changeOrigin: true,
          }
        }
    },
    
    runtimeCompiler: true,
    pages: {
      default: {
        entry: 'src/main.js',
        template: 'public/index.html',
        filename: 'index.html'
      },
      login: {
        entry: 'src/main.js',
        template: 'public/index.html',
        filename: 'login.html'
      }
    },
}

