import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'jwtAuth',
  description: 'Documentation for the jwtAuth module',
  srcDir: 'docs',  
  outDir: '.vitepress/dist',
  cleanUrls: true,
  lang: 'en-US',


  themeConfig: {
    siteTitle: 'jwtAuth',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'Docs',  link: '/README' },
      { text: 'Bot Detector Docs',  link: '/@riavzon/botdetector/README' },
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Introduction', link: '/README' },
          { text: 'Bot Detection',  link: '/@riavzon/botdetector/README' }
        ]
      },
      {
        text: 'Core API',
        items: [
          { text: 'API', link: '/globals' },
          { text: 'Bot Detection API', link: '/@riavzon/botdetector/globals' }
        ]
      }
    ],

    search: { provider: 'local' },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/riavzon/jwtauth' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: '© 2025–present Sergio Riavzon'
    }
  },


})
