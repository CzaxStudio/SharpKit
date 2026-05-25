
Object subclass: #WorkerPool
    instanceVariableNames: 'workers taskQueue results mutex'
    classVariableNames: ''
    package: 'AdvancedConcurrency'.


WorkerPool >> initializeWithWorkers: anInteger [
    taskQueue := SharedQueue new.
    results := OrderedCollection new.
    mutex := Mutex new.
    workers := OrderedCollection new.
    
    
    anInteger timesRepeat: [
        workers add: ([ self startWorkerLoop ] forkNamed: 'WorkerThread').
    ].
    ^ self.
]


WorkerPool >> startWorkerLoop [
    [ true ] whileTrue: [ | task result |
       
        task := taskQueue next. 
        
        
        result := task value. 
        
        
        mutex critical: [ 
            results add: result. 
        ].
    ].
]


WorkerPool >> submitTask: aBlock [
    taskQueue nextPut: aBlock.


"Test"
| pool |
"Create a pool with 4 concurrent background workers"
pool := WorkerPool new initializeWithWorkers: 4.

"Submit 5 heavy mathematical tasks to the queue asynchronously"
pool submitTask: [ 5000 factorial ].
pool submitTask: [ 6000 factorial ].
pool submitTask: [ 7000 factorial ].
pool submitTask: [ 8000 factorial ].
pool submitTask: [ 9000 factorial ].

"Pause the main thread for 1 second to let workers finish processing"
(Delay forSeconds: 1) wait.

"Inspect the safely accumulated results array"
pool inspect.

