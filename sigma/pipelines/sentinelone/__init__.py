from .sentinelone import sentinelone_pipeline
from .sentinelone_pq import sentinelonepq_pipeline

pipelines = {
    "sentinelone_pipeline": sentinelone_pipeline,
    "sentinelonepq_pipeline": sentinelonepq_pipeline,
}