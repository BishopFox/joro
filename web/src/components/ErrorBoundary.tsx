import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

// ErrorBoundary contains render/lifecycle exceptions so a fault in one page
// doesn't unmount the whole SPA (which would blank every panel and force a
// manual refresh). The Zustand stores keep their data, so remounting after a
// reset — or navigating to another tab — restores the UI.
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('UI error boundary caught:', error, info.componentStack)
  }

  reset = () => this.setState({ error: null })

  render() {
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-3 p-6 text-center">
          <span className="text-sm font-semibold text-semantic-error uppercase tracking-wide">
            Something went wrong
          </span>
          <span className="text-xs text-content-muted max-w-md break-words">
            {this.state.error.message || 'An unexpected error occurred rendering this view.'}
          </span>
          <div className="flex gap-2">
            <button
              onClick={this.reset}
              className="px-3 py-1.5 bg-surface-input text-content-primary text-xs font-medium rounded border border-border hover:bg-surface-hover"
            >
              Try again
            </button>
            <button
              onClick={() => window.location.reload()}
              className="px-3 py-1.5 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
            >
              Reload
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
