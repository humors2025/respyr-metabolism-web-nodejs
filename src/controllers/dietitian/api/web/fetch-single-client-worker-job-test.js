/**
 * Temporary test controller
 * Used to verify that the Lambda and Express route are working.
 */

const fetchSingleClientWorkerJobTest = async (req, res) => {
  try {
    console.log("fetch-single-client-worker-job-test API called");

    return res.status(200).json({
      success: true,
      statusCode: 200,
      message: "Fetch single client worker job test API is working successfully",
      method: req.method,
      path: req.originalUrl,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error(
      "Error in fetchSingleClientWorkerJobTest:",
      error
    );

    return res.status(500).json({
      success: false,
      statusCode: 500,
      message: "Internal server error",
      error:
        process.env.NODE_ENV === "production"
          ? undefined
          : error.message,
    });
  }
};

module.exports = {
  fetchSingleClientWorkerJobTest,
};