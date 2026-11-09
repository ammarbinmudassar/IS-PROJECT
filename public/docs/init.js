window.addEventListener('DOMContentLoaded', () => {
  window.ui = SwaggerUIBundle({
    url: '/openapi.json', dom_id: '#swagger-ui', validatorUrl: null,
    persistAuthorization: false, withCredentials: true,
    requestInterceptor: async request => {
      const url = new URL(request.url, location.href);
      if (url.origin === location.origin && url.pathname.startsWith('/api/') && request.method.toUpperCase() !== 'GET' && url.pathname !== '/api/login') {
        const response = await fetch('/api/me', { credentials: 'same-origin' });
        if (response.ok) request.headers['X-CSRF-Token'] = (await response.json()).csrf;
      }
      return request;
    }
  });
});
