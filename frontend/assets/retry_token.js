document.body.addEventListener('htmx:responseError', function (evt) {
  if (evt.detail.xhr.status === 401) {
    console.log('Error 401')
    evt.preventDefault(); // stop htmx from swapping the error response

    fetch('/auth/refresh', {
      method: 'POST',
      credentials: 'include', // send refresh token cookie
    })
    .then(res => {
      if (!res.ok) throw new Error('refresh failed');
      return res.json(); // or just rely on new Set-Cookie header
    })
    .then(() => {
      // retry the original request that got the 401
      htmx.ajax(evt.detail.requestConfig.verb,
                evt.detail.requestConfig.path,
                evt.detail.requestConfig.elt);
    })
    .catch(() => {
      window.location.href = '/login';
    });
  }
});
