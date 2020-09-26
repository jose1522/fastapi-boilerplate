def compareDictStructures(realDict:dict, sampleDict:dict):
    sample_keys = set(realDict.keys())
    real_keys = set(sampleDict.keys())
    intersect_keys = sample_keys.intersection(real_keys)
    result = {'added': sample_keys - real_keys,
              'removed': real_keys - sample_keys,
              'modified': {o: (realDict[o], sampleDict[o]) for o in intersect_keys if realDict[o] != sampleDict[o]},
              'same': set(o for o in intersect_keys if realDict[o] == sampleDict[o])
              }
    return result

def doDictStructuresMatch(realDict:dict, sampleDict:dict):
    result = compareDictStructures(realDict,sampleDict)
    return len(result['added']) == 0 and len(result['removed']) == 0