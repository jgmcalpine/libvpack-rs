import { useEffect, useState } from 'react'
import initWasm, { init as setPanicHook } from './wasm/wasm_vpack'

type EngineStatus = 'Loading' | 'Ready' | 'Error'

function App() {
  const [engineStatus, setEngineStatus] = useState<EngineStatus>('Loading')

  useEffect(() => {
    const initializeWasm = async () => {
      try {
        await initWasm()
        setPanicHook()
        setEngineStatus('Ready')
      } catch (error) {
        console.error('Failed to initialize WASM module:', error)
        setEngineStatus('Error')
      }
    }

    initializeWasm()
  }, [])

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4 text-gray-900 dark:text-white">
          VTXO Inspector
        </h1>
        <div className="text-xl text-gray-700 dark:text-gray-300">
          VTXO Engine: <span className="font-semibold">{engineStatus}</span>
        </div>
      </div>
    </div>
  )
}

export default App
