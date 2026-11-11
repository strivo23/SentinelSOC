"""Confusion-matrix evaluation against explicitly labelled scenario ids."""
def evaluate(labels, predictions):
    """Each row is a scenario with boolean ground_truth and detected values."""
    tp=fp=tn=fn=0
    for row in labels:
        actual = bool(row["ground_truth"]); predicted = bool(predictions.get(row["scenario_id"], False))
        if actual and predicted: tp += 1
        elif not actual and predicted: fp += 1
        elif not actual: tn += 1
        else: fn += 1
    div = lambda a,b: a/b if b else 0.0
    precision=div(tp,tp+fp); recall=div(tp,tp+fn); f1=div(2*precision*recall,precision+recall)
    return {"TP":tp,"FP":fp,"TN":tn,"FN":fn,"precision":precision,"recall":recall,
            "f1_score":f1,"detection_rate":recall,"false_positive_rate":div(fp,fp+tn)}
