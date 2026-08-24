
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) {
    return meta.getAttribute('content');
  }
  return null;
}

export const fetchWrapper = {
  get,
  getRaw,
  post,
  postRaw,
  postWithProgress,
  put,
  putRaw,
  patch,
  delete: _delete,
  deleteRaw,
}

function get(url: string) {
  const requestOptions = {
    method: 'GET',
    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    credentials: 'include' as RequestCredentials,
  }
  return fetch(url, requestOptions).then(handleResponse)
}

function getRaw(url: string) {
  const requestOptions = {
    method: 'GET',
    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    credentials: 'include' as RequestCredentials,
  }
  return fetch(url, requestOptions)
}

interface FetchWrapperOptions {
  signal?: AbortSignal
  keepalive?: boolean
}

function post(url: string, body: unknown, options: FetchWrapperOptions = {}) {
  const isFormData = body instanceof FormData;
  const requestOptions: RequestInit = {
    method: 'POST',
    headers: isFormData
      ? { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-TOKEN': getCsrfToken() || '' }
      : { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': getCsrfToken() || '' },
    credentials: 'include' as RequestCredentials,
    body: isFormData ? body : JSON.stringify(body),
  }
  if (options.signal) {
    requestOptions.signal = options.signal
  }
  return fetch(url, requestOptions).then(handleResponse)
}

function postRaw(url: string, body: unknown, options: FetchWrapperOptions = {}) {
  const isFormData = body instanceof FormData;
  const requestOptions: RequestInit = {
    method: 'POST',
    headers: isFormData
      ? { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-TOKEN': getCsrfToken() || '' }
      : { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': getCsrfToken() || '' },
    credentials: 'include' as RequestCredentials,
    body: isFormData ? body : JSON.stringify(body),
  }
  if (options.signal) {
    requestOptions.signal = options.signal
  }
  return fetch(url, requestOptions)
}

// Like `post` for a FormData body, but implemented with XMLHttpRequest instead of
// fetch() so callers can report upload progress — fetch() has no upload-progress event.
// Use this for large file uploads where the UI wants to show percent-complete.
function postWithProgress(url: string, formData: FormData, onProgress?: (percent: number) => void): Promise<any> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', url)
    xhr.setRequestHeader('Accept', 'application/json')
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')
    xhr.setRequestHeader('X-CSRF-TOKEN', getCsrfToken() || '')
    xhr.withCredentials = true

    if (onProgress) {
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          onProgress(Math.round((event.loaded / event.total) * 100))
        }
      }
    }

    xhr.onload = () => {
      let data: any = null
      if (xhr.responseText) {
        try {
          data = JSON.parse(xhr.responseText)
        } catch (e) {
          // response wasn't JSON (could be an HTML redirect to login), keep raw text
          data = xhr.responseText
        }
      }

      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(data)
        return
      }

      // Mirror handleResponse's error-message preference: a backend `message` or
      // `error` field, falling back to the HTTP status text.
      const message = (data && (data.message || data.error)) || xhr.statusText || `Upload failed: HTTP ${xhr.status}`
      reject(new Error(message))
    }

    xhr.onerror = () => reject(new Error('Network error during upload'))
    xhr.send(formData)
  })
}

function patch(url: string, body: any) {
  const requestOptions: RequestInit = {
    method: 'PATCH',
    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': getCsrfToken() || '' },
    credentials: 'include' as RequestCredentials,
    body: JSON.stringify(body),
  }
  return fetch(url, requestOptions).then(handleResponse)
}

function put(url: string, body: any, options: FetchWrapperOptions = {}) {
  const requestOptions: RequestInit = {
    method: 'PUT',
    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': getCsrfToken() || '' },
    credentials: 'include' as RequestCredentials,
    body: JSON.stringify(body),
  }
  if (options.keepalive) requestOptions.keepalive = true
  return fetch(url, requestOptions).then(handleResponse)
}

// Like `put`, but returns the raw Response so callers can inspect the status
// code and error body (e.g. HTTP 409 lease conflicts) instead of the flattened
// error-message string that `handleResponse` rejects with.
function putRaw(url: string, body: unknown, options: FetchWrapperOptions = {}) {
  const requestOptions: RequestInit = {
    method: 'PUT',
    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': getCsrfToken() || '' },
    credentials: 'include' as RequestCredentials,
    body: JSON.stringify(body),
  }
  if (options.keepalive) requestOptions.keepalive = true
  return fetch(url, requestOptions)
}

// Raw variant: returns the Response untouched so callers can read a structured error body.
// handleResponse collapses an error to its `message` string, which discards the `blockers`
// array a guarded refusal carries — and the blockers are the part that tells a human what to
// do about it.
function deleteRaw(url: string, body: unknown = {}, options: FetchWrapperOptions = {}) {
  const requestOptions: RequestInit = {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': getCsrfToken() || '',
    },
    credentials: 'include' as RequestCredentials,
    body: JSON.stringify(body),
  }
  if (options.keepalive) requestOptions.keepalive = true
  return fetch(url, requestOptions)
}

// prefixed with underscored because delete is a reserved word in javascript
function _delete(url: string, body: any, options: FetchWrapperOptions = {}) {
  const requestOptions: RequestInit = {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': getCsrfToken() || ''
    },
    credentials: 'include',
    body: JSON.stringify(body),
  }
  if (options.keepalive) requestOptions.keepalive = true
  return fetch(url, requestOptions).then(handleResponse)
}

// helper functions
function handleResponse(response: Response) {
  return response.text().then((text) => {
    let data: any = null
    if (text) {
      try {
        data = JSON.parse(text)
      } catch (e) {
        // response wasn't JSON (could be an HTML redirect to login), keep raw text
        data = text
      }
    }

    if (!response.ok) {
      // Prefer the backend's error text. Many controllers return `{ message: ... }`,
      // but a large number return `{ error: ... }` instead (e.g. GenAiImportService's
      // "Job not found." 404); fall back to that before the generic HTTP statusText so
      // users see the specific, actionable message rather than "Not Found".
      const error = (data && (data.message || data.error)) || response.statusText
      return Promise.reject(error)
    }

    return data
  })
}
