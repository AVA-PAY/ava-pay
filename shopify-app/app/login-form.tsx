/**
 * Shop-domain form shown on the two non-embedded entry points: the app URL
 * itself and the configured login path. Both routes hand their `login()`
 * result to this component.
 *
 * Deliberately plain markup. These pages render outside the Shopify admin,
 * before any session exists, so they pull in neither App Bridge nor Polaris.
 */
export function LoginForm({ shopError }: { shopError?: string }) {
  return (
    <main
      style={{
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        maxWidth: '32rem',
        margin: '4rem auto',
        padding: '0 1.5rem',
        color: '#1a1a1a',
      }}
    >
      <h1 style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>AVA Pay</h1>
      <p style={{ marginTop: 0, color: '#4a4a4a', lineHeight: 1.5 }}>
        See which AI shopping agents visit your store, verify the credentials
        they carry, and apply your own policy to that traffic.
      </p>

      <form method="get" action="/auth/login" style={{ marginTop: '2rem' }}>
        <label
          htmlFor="shop"
          style={{ display: 'block', fontWeight: 600, marginBottom: '0.5rem' }}
        >
          Shop domain
        </label>
        <input
          id="shop"
          name="shop"
          type="text"
          required
          autoComplete="off"
          spellCheck={false}
          placeholder="my-shop.myshopify.com"
          aria-describedby={shopError ? 'shop-error' : undefined}
          style={{
            width: '100%',
            padding: '0.6rem 0.75rem',
            fontSize: '1rem',
            border: `1px solid ${shopError ? '#c62828' : '#8c9196'}`,
            borderRadius: '0.5rem',
            boxSizing: 'border-box',
          }}
        />
        {shopError ? (
          <p
            id="shop-error"
            role="alert"
            style={{ color: '#c62828', fontSize: '0.9rem', marginTop: '0.5rem' }}
          >
            Enter a shop domain like my-shop.myshopify.com
          </p>
        ) : null}
        <button
          type="submit"
          style={{
            marginTop: '1rem',
            padding: '0.6rem 1.25rem',
            fontSize: '1rem',
            color: '#ffffff',
            background: '#1a1a1a',
            border: 'none',
            borderRadius: '0.5rem',
            cursor: 'pointer',
          }}
        >
          Install or log in
        </button>
      </form>
    </main>
  );
}
