
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
