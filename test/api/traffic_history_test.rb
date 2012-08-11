require "helper"

describe Alexa::API::TrafficHistory do
  it "defaults start to be in range to current time" do
    stub_request(:get, %r{http://awis.amazonaws.com}).to_return(:body => "ok")
    @traffic_history = Alexa::API::TrafficHistory.new(:access_key_id => "fake", :secret_access_key => "fake")
    @traffic_history.fetch(:url => "github.com", :range => 14)

    # 14 days from now
    assert_in_delta (Time.now - 3600 * 24 * 14).to_i, @traffic_history.start.to_i, 0.001
  end

  describe "parsing xml" do
    before do
      stub_request(:get, %r{http://awis.amazonaws.com}).to_return(fixture("traffic_history/github.txt"))
      @traffic_history = Alexa::API::TrafficHistory.new(:access_key_id => "fake", :secret_access_key => "fake")
      @traffic_history.fetch(:url => "amazon.com")
    end

    it "returns data" do
      assert_equal 28, @traffic_history.data.size
    end
  end
end
