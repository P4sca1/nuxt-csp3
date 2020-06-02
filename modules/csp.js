import { randomBytes } from 'crypto'

export default function cspModule() {
  // Set nuxt CSP options.
  this.options.render.csp = {
    reportOnly: true,
    hashAlgorithm: 'sha256',
    // Make sure unsafe-inline is always sent along with generated hashes to support browsers not compatible with CSP2.
    unsafeInlineCompatibility: true,
    policies: {
      // https://csp.withgoogle.com/docs/strict-csp.html
      'script-src': [
        // A random nonce as well as hashes for inline scripts are added to script-src
        // by nuxt.
        // Allow the execution of scripts dynamically added to the page, as long as they were loaded by a safe, already-trusted script.
        // This requires CSP3. Browsers that support this will ignore unsafe-inline, unsafe-eval, self and host based source lists.
        "'strict-dynamic'",
        // Allow unsafe inline scripts. This is used as a fallback for browsers that do not support CSP2.
        // Browsers supporting CSP2 will ignore unsafe-inline because we set a nonce and hashes.
        "'unsafe-inline'",
        // Allow scripts to be loaded from all hosts. This is used as a fallback for browsers that do not support CSP3
        // to make our site compatible with those older browsers. We don't have full protection in those older browsers.
        'https:',
        'http:',
      ],
      // Prevents fetching and executing plugin resources embedded using <object>, <embed> or <applet> tags.
      // The most common example is Flash.
      'object-src': ["'none'"],
      // Disables <base> URIs, preventing attackers from changing the locations of scripts loaded from relative URLs.
      'base-uri': ["'none'"],
      'require-trusted-types-for': ["'script'"],
    },
  }

  this.nuxt.hook('render:routeContext', (nuxtContext) => {
    // Generate a 128 bit random nonce every request.
    const nonce = randomBytes(128).toString('base64')
    // Inject nonce into vuex state before state is serialized into window.__NUXT__.
    nuxtContext.state.nonce = nonce
  })

  this.nuxt.hook(
    'render:route',
    (url, { cspScriptSrcHashes }, { nuxt: nuxtContext }) => {
      // Extract nonce generated in render:routeContext.
      const nonce = nuxtContext.state.nonce
      // Add nonce to cspScriptSrcHashes. Nuxt will populate all entries in this array
      // to the csp header and meta tags as part of the script-src csp policy.
      cspScriptSrcHashes.push(`'nonce-${nonce}'`)
    }
  )
}
