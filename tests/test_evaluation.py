from core.evaluation import evaluate

def test_confusion_matrix_metrics_and_zero_division():
    labels=[{"scenario_id":str(i),"ground_truth":x} for i,x in enumerate([1,1,0,0])]
    got=evaluate(labels,{"0":True,"1":False,"2":True,"3":False})
    assert (got["TP"],got["FP"],got["TN"],got["FN"])==(1,1,1,1)
    assert got["precision"]==.5 and got["recall"]==.5 and got["f1_score"]==.5
    assert evaluate([],{})["false_positive_rate"]==0
